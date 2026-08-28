package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	tlsCAPath   = "/var/lib/4so-platform-installer/secrets/platform-ca.crt"
	tlsCertPath = "/var/lib/4so-platform-installer/secrets/platform-tls.crt"
	tlsKeyPath  = "/var/lib/4so-platform-installer/secrets/platform-tls.key"
)

func ensureTLSMaterial(system System, publicEndpoint, dnsZone string) error {
	if system.Exists(tlsCAPath) && system.Exists(tlsCertPath) && system.Exists(tlsKeyPath) {
		return nil
	}
	endpoint, err := url.Parse(publicEndpoint)
	if err != nil || endpoint.Hostname() == "" {
		return fmt.Errorf("public endpoint hostname is required for TLS material")
	}
	hosts := []string{endpoint.Hostname()}
	zone := strings.TrimSpace(dnsZone)
	if zone != "" {
		hosts = append(hosts, "git."+zone, "registry."+zone, "auth."+zone, "agent."+zone)
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: "4SO Platform Factory Bootstrap CA"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{
		SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: endpoint.Hostname()},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: uniqueStrings(hosts),
	}
	if ip := net.ParseIP(endpoint.Hostname()); ip != nil {
		leaf.IPAddresses = append(leaf.IPAddresses, ip)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	if err = system.WriteFile(tlsCAPath, caPEM, 0o644); err != nil {
		return err
	}
	if err = system.WriteFile(tlsCertPath, certPEM, 0o600); err != nil {
		return err
	}
	return system.WriteFile(tlsKeyPath, keyPEM, 0o600)
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil || value.Sign() == 0 {
		return big.NewInt(time.Now().UnixNano())
	}
	return value
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
