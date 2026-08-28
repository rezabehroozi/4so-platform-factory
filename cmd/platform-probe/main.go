package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"platform.4so.io/factory/internal/buildinfo"
	"platform.4so.io/factory/internal/daemoncli"
	"strings"
	"time"
)

var version = buildinfo.Version

type result struct {
	Version        string   `json:"version"`
	Target         string   `json:"target"`
	DNSResolved    bool     `json:"dnsResolved"`
	Addresses      []string `json:"addresses,omitempty"`
	TCPConnected   bool     `json:"tcpConnected"`
	StorageWritten bool     `json:"storageWritten,omitempty"`
	StorageRead    bool     `json:"storageRead,omitempty"`
	DurationMillis int64    `json:"durationMillis"`
	Error          string   `json:"error,omitempty"`
}

func main() {
	action, cliErr := daemoncli.Parse(os.Args[1:])
	if cliErr != nil {
		fmt.Fprintln(os.Stderr, cliErr)
		fmt.Fprintln(os.Stderr, daemoncli.Usage(filepath.Base(os.Args[0])))
		os.Exit(2)
	}
	switch action {
	case daemoncli.Help:
		fmt.Println(daemoncli.Usage(filepath.Base(os.Args[0])))
		return
	case daemoncli.Version:
		fmt.Println(version)
		return
	}
	started := time.Now()
	storagePath := strings.TrimSpace(os.Getenv("PLATFORM_PROBE_STORAGE_PATH"))
	if storagePath != "" {
		runStorageProbe(started, storagePath)
		return
	}
	listenPort := strings.TrimSpace(os.Getenv("PLATFORM_PROBE_LISTEN_PORT"))
	if listenPort != "" {
		runTCPServer(listenPort)
		return
	}
	host := strings.TrimSpace(os.Getenv("PLATFORM_PROBE_HOST"))
	if host == "" {
		host = "kubernetes.default.svc"
	}
	port := strings.TrimSpace(os.Getenv("PLATFORM_PROBE_PORT"))
	if port == "" {
		port = "443"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out := result{Version: version, Target: net.JoinHostPort(host, port)}
	addresses, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		out.Error = "dns lookup failed: " + err.Error()
		finish(out, started, 1)
	}
	out.DNSResolved = len(addresses) > 0
	out.Addresses = addresses
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", out.Target)
	if err != nil {
		out.Error = "tcp connection failed: " + err.Error()
		finish(out, started, 1)
	}
	_ = conn.Close()
	out.TCPConnected = true
	finish(out, started, 0)
}

func runTCPServer(port string) {
	if _, err := net.LookupPort("tcp", port); err != nil {
		fmt.Fprintln(os.Stderr, "invalid listen port:", err)
		os.Exit(2)
	}
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen failed:", err)
		os.Exit(1)
	}
	defer listener.Close()
	if err := serveTCP(listener); err != nil {
		fmt.Fprintln(os.Stderr, "accept failed:", err)
		os.Exit(1)
	}
}

func serveTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("4so-platform-probe\n"))
		_ = conn.Close()
	}
}

func runStorageProbe(started time.Time, storagePath string) {
	out, err := storageProbe(storagePath)
	if err != nil {
		out.Error = err.Error()
		finish(out, started, 1)
	}
	finish(out, started, 0)
}

func storageProbe(storagePath string) (result, error) {
	out := result{Version: version, Target: storagePath}
	marker := strings.TrimSpace(os.Getenv("PLATFORM_PROBE_STORAGE_MARKER"))
	if marker == "" || len(marker) > 512 {
		return out, fmt.Errorf("storage marker must be non-empty and at most 512 bytes")
	}
	clean := filepath.Clean(storagePath)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return out, fmt.Errorf("storage path must be an absolute file path")
	}
	verifyOnly := strings.EqualFold(strings.TrimSpace(os.Getenv("PLATFORM_PROBE_STORAGE_VERIFY_ONLY")), "true")
	if !verifyOnly {
		if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
			return out, fmt.Errorf("create storage probe directory: %w", err)
		}
		if err := os.WriteFile(clean, []byte(marker), 0o640); err != nil {
			return out, fmt.Errorf("write storage probe marker: %w", err)
		}
		out.StorageWritten = true
	}
	raw, err := os.ReadFile(clean)
	if err != nil {
		return out, fmt.Errorf("read storage probe marker: %w", err)
	}
	if string(raw) != marker {
		return out, fmt.Errorf("storage probe marker mismatch")
	}
	out.StorageRead = true
	return out, nil
}

func probeTerminationMessagePath() string {
	path := strings.TrimSpace(os.Getenv("PLATFORM_PROBE_TERMINATION_MESSAGE_PATH"))
	if path == "" {
		path = "/dev/termination-log"
	}
	return path
}

func writeProbeTerminationMessage(path string, out result) error {
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	// Kubernetes stores at most a few KiB of termination message. Probe output
	// is intentionally compact; fail instead of writing truncated invalid JSON.
	if len(raw) > 4096 {
		return fmt.Errorf("probe termination message exceeds 4096 bytes")
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func finish(out result, started time.Time, code int) {
	out.DurationMillis = time.Since(started).Milliseconds()
	_ = json.NewEncoder(os.Stdout).Encode(out)
	_ = writeProbeTerminationMessage(probeTerminationMessagePath(), out)
	os.Exit(code)
}
