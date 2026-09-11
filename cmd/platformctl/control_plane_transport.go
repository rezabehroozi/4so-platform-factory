package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const platformctlControlPlaneTransportAuthority = "PLATFORMCTL_CONTROL_PLANE_TRANSPORT_AUTHORITY_V1"

type controlPlaneLookupFunc func(context.Context, string, string) ([]netip.Addr, error)
type controlPlaneDialFunc func(context.Context, string, string) (net.Conn, error)

func controlPlaneAddressBlocked(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return false
	}
	if !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		v := addr.As4()
		return v[0] == 0
	}
	return false
}

func resolveControlPlaneHost(ctx context.Context, host string, lookup controlPlaneLookupFunc) ([]netip.Addr, error) {
	host = strings.TrimSpace(host)
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	addresses, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve platform control-plane target %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("platform control-plane target %q resolved to no addresses", host)
	}
	out := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		out = append(out, address.Unmap())
	}
	return out, nil
}

func newClosureHTTPClient(caFile string, lookup controlPlaneLookupFunc, dial controlPlaneDialFunc) (*http.Client, error) {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	if dial == nil {
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Credential-bearing platform control-plane traffic is an explicit trust
	// boundary. Environment proxies are intentionally ignored: a proxy must not
	// become an undeclared bearer-token/TLS trust hop. Resolve once per socket
	// attempt, validate that exact address set, and dial only those admitted IPs.
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid platform control-plane target %q: %w", address, err)
		}
		addresses, err := resolveControlPlaneHost(ctx, host, lookup)
		if err != nil {
			return nil, err
		}
		for _, addr := range addresses {
			if controlPlaneAddressBlocked(addr) {
				return nil, fmt.Errorf("platform control-plane target resolves to an unsafe address: %s", addr)
			}
		}
		var lastErr error
		for _, addr := range addresses {
			if network == "tcp4" && !addr.Is4() {
				continue
			}
			if network == "tcp6" && addr.Is4() {
				continue
			}
			conn, dialErr := dial(ctx, network, net.JoinHostPort(addr.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("platform control-plane target has no address compatible with %s", network)
		}
		return nil, lastErr
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(caFile) != "" {
		raw, err := readLimitedFile(caFile, 2<<20)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("ca-file does not contain a valid PEM certificate")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("platform API redirects are denied to preserve endpoint authority and credentials")
		},
	}, nil
}

func readPrivateTokenFile(path string, limit int64) ([]byte, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("token file must be a regular non-symlink file")
	}
	if before.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("token file permissions must not allow group/other access")
	}
	if before.Size() <= 0 || before.Size() > limit {
		return nil, fmt.Errorf("token file must contain 1-%d bytes", limit)
	}
	flags := os.O_RDONLY
	flags |= syscall.O_NOFOLLOW
	fd, err := os.OpenFile(absolute, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open token file safely: %w", err)
	}
	defer fd.Close()
	opened, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("token file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(fd, limit+1))
	if err == nil && int64(len(raw)) > limit {
		err = fmt.Errorf("token file exceeds %d bytes", limit)
	}
	if err != nil {
		return nil, err
	}
	after, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(opened, after) || after.Size() != opened.Size() || after.ModTime() != opened.ModTime() {
		return nil, errors.New("token file changed while reading")
	}
	return raw, nil
}
