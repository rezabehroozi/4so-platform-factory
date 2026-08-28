package hostdeployment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultHealthPath      = "/healthz"
	defaultHealthTimeout   = 30 * time.Second
	defaultHealthInterval  = 500 * time.Millisecond
	maximumHealthBodyBytes = 64 * 1024
)

type ServiceIntent struct {
	Enable bool `json:"enable"`
	Start  bool `json:"start"`
}

type HealthPlan struct {
	URL                  string `json:"url"`
	DialAddress          string `json:"dialAddress"`
	ServerName           string `json:"serverName,omitempty"`
	CertificateFile      string `json:"certificateFile,omitempty"`
	Path                 string `json:"path"`
	TimeoutSeconds       int    `json:"timeoutSeconds"`
	IntervalMilliseconds int    `json:"intervalMilliseconds"`
}

type HealthStatus struct {
	Ready      bool      `json:"ready"`
	URL        string    `json:"url"`
	Status     string    `json:"status,omitempty"`
	Version    string    `json:"version,omitempty"`
	HTTPStatus int       `json:"httpStatus,omitempty"`
	Attempts   int       `json:"attempts"`
	CheckedAt  time.Time `json:"checkedAt,omitempty"`
	LastError  string    `json:"lastError,omitempty"`
}

type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

func buildHealthPlan(spec Spec, deployedCertificatePath string) (HealthPlan, error) {
	path := strings.TrimSpace(spec.Spec.Health.Path)
	if path == "" {
		path = defaultHealthPath
	}
	parsedPath, err := url.Parse(path)
	if err != nil || !strings.HasPrefix(path, "/") || parsedPath.IsAbs() || parsedPath.Host != "" || parsedPath.RawQuery != "" || parsedPath.Fragment != "" {
		return HealthPlan{}, errors.New("health.path must be an absolute path without query or fragment")
	}
	timeout := time.Duration(spec.Spec.Health.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = defaultHealthTimeout
	}
	if timeout < time.Second || timeout > 5*time.Minute {
		return HealthPlan{}, errors.New("health.timeoutSeconds must be between 1 and 300")
	}
	interval := time.Duration(spec.Spec.Health.IntervalMilliseconds) * time.Millisecond
	if interval == 0 {
		interval = defaultHealthInterval
	}
	if interval < 100*time.Millisecond || interval > 5*time.Second {
		return HealthPlan{}, errors.New("health.intervalMilliseconds must be between 100 and 5000")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(spec.Spec.Listen))
	if err != nil || strings.TrimSpace(port) == "" {
		return HealthPlan{}, fmt.Errorf("listen must be host:port for readiness verification: %w", err)
	}
	dialHost := strings.Trim(host, "[]")
	switch dialHost {
	case "", "0.0.0.0":
		dialHost = "127.0.0.1"
	case "::":
		dialHost = "::1"
	}
	dialAddress := net.JoinHostPort(dialHost, port)
	plan := HealthPlan{
		DialAddress:          dialAddress,
		Path:                 path,
		TimeoutSeconds:       int(timeout / time.Second),
		IntervalMilliseconds: int(interval / time.Millisecond),
	}
	certificateSource := strings.TrimSpace(spec.Spec.TLS.CertificateFile)
	if certificateSource == "" {
		plan.URL = "http://" + dialAddress + path
		return plan, nil
	}
	serverName, err := certificateServerName(certificateSource, dialHost, strings.TrimSpace(spec.Spec.Health.ServerName))
	if err != nil {
		return HealthPlan{}, err
	}
	plan.ServerName = serverName
	plan.CertificateFile = deployedCertificatePath
	plan.URL = "https://" + net.JoinHostPort(serverName, port) + path
	return plan, nil
}

func certificateServerName(path, preferredHost, explicitServerName string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read TLS certificate for readiness probe: %w", err)
	}
	certs, err := parseCertificates(raw)
	if err != nil || len(certs) == 0 {
		return "", fmt.Errorf("parse TLS certificate for readiness probe: %w", err)
	}
	leaf := certs[0]
	if explicitServerName != "" {
		if strings.ContainsAny(explicitServerName, "/:@") {
			return "", errors.New("health.serverName must be a DNS name or IP address without port")
		}
		if err := leaf.VerifyHostname(explicitServerName); err != nil {
			return "", fmt.Errorf("health.serverName is not covered by the TLS certificate: %w", err)
		}
		return explicitServerName, nil
	}
	preferredIP := net.ParseIP(preferredHost)
	if preferredIP != nil {
		for _, candidate := range leaf.IPAddresses {
			if candidate.Equal(preferredIP) {
				return preferredHost, nil
			}
		}
	} else if preferredHost != "" {
		for _, candidate := range leaf.DNSNames {
			if strings.EqualFold(candidate, preferredHost) {
				return preferredHost, nil
			}
		}
	}
	for _, candidate := range leaf.DNSNames {
		if !strings.Contains(candidate, "*") {
			return candidate, nil
		}
	}
	if len(leaf.DNSNames) > 0 {
		return "", errors.New("wildcard-only TLS certificate requires health.serverName with a concrete covered hostname")
	}
	if len(leaf.IPAddresses) > 0 {
		return leaf.IPAddresses[0].String(), nil
	}
	return "", errors.New("TLS certificate must contain a DNS or IP subject alternative name for readiness verification")
}

func parseCertificates(raw []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	remaining := raw
	for len(strings.TrimSpace(string(remaining))) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("certificate file contains invalid PEM data")
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("certificate file does not contain parseable certificates")
	}
	return certs, nil
}

func probeHealth(ctx context.Context, plan HealthPlan, expectedVersion string, now func() time.Time) (HealthStatus, error) {
	status := HealthStatus{URL: plan.URL}
	if now == nil {
		now = time.Now
	}
	if strings.TrimSpace(plan.URL) == "" || strings.TrimSpace(plan.DialAddress) == "" {
		return status, errors.New("readiness plan is incomplete")
	}
	timeout := time.Duration(plan.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = defaultHealthTimeout
	}
	interval := time.Duration(plan.IntervalMilliseconds) * time.Millisecond
	if interval <= 0 {
		interval = defaultHealthInterval
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := readinessHTTPClient(plan)
	if err != nil {
		status.LastError = err.Error()
		return status, err
	}
	defer client.CloseIdleConnections()
	var lastErr error
	for {
		status.Attempts++
		response, probeErr := probeHealthOnce(probeCtx, client, plan.URL, expectedVersion)
		status.HTTPStatus = response.HTTPStatus
		status.Status = response.Status
		status.Version = response.Version
		status.CheckedAt = now().UTC()
		if probeErr == nil {
			status.Ready = true
			status.LastError = ""
			return status, nil
		}
		lastErr = probeErr
		status.LastError = probeErr.Error()
		select {
		case <-probeCtx.Done():
			return status, fmt.Errorf("installer readiness probe failed after %d attempts: %w", status.Attempts, lastErr)
		case <-time.After(interval):
		}
	}
}

func readinessHTTPClient(plan HealthPlan) (*http.Client, error) {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, plan.DialAddress)
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     true,
	}
	if strings.HasPrefix(plan.URL, "https://") {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		raw, err := os.ReadFile(plan.CertificateFile)
		if err != nil {
			return nil, fmt.Errorf("read deployed TLS certificate for readiness probe: %w", err)
		}
		if !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("deployed TLS certificate cannot be added to readiness trust roots")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: plan.ServerName}
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("readiness endpoint redirects are not allowed")
		},
	}, nil
}

func probeHealthOnce(ctx context.Context, client *http.Client, endpoint, expectedVersion string) (HealthStatus, error) {
	status := HealthStatus{URL: endpoint}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return status, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return status, err
	}
	defer response.Body.Close()
	status.HTTPStatus = response.StatusCode
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumHealthBodyBytes))
		return status, fmt.Errorf("readiness endpoint returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maximumHealthBodyBytes+1))
	decoder.DisallowUnknownFields()
	var payload healthResponse
	if err = decoder.Decode(&payload); err != nil {
		return status, fmt.Errorf("decode readiness response: %w", err)
	}
	if err = ensureJSONEOF(decoder); err != nil {
		return status, err
	}
	status.Status = payload.Status
	status.Version = payload.Version
	if payload.Status != "ok" {
		return status, fmt.Errorf("readiness status is %q", payload.Status)
	}
	if payload.Version != expectedVersion {
		return status, fmt.Errorf("readiness version %q does not match deployment version %q", payload.Version, expectedVersion)
	}
	return status, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("readiness response contains multiple JSON values")
		}
		return fmt.Errorf("read readiness response trailer: %w", err)
	}
	return nil
}
