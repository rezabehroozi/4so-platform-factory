package agentpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

const DefaultLifetime = 30 * 24 * time.Hour

type Signer struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	now     func() time.Time
}

type Issued struct {
	CertificatePEM   string
	CACertificatePEM string
	SerialNumber     string
	Fingerprint      string
	Subject          string
	NotBefore        time.Time
	NotAfter         time.Time
}

func GenerateCA(commonName string, now time.Time, lifetime time.Duration) ([]byte, []byte, error) {
	if strings.TrimSpace(commonName) == "" {
		commonName = "4SO Platform Factory Agent CA"
	}
	if lifetime <= 0 {
		lifetime = 10 * 365 * 24 * time.Hour
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"4SO Platform Factory"}},
		NotBefore:    now.UTC().Add(-5 * time.Minute), NotAfter: now.UTC().Add(lifetime),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func NewSigner(certPEM, keyPEM []byte, now func() time.Time) (*Signer, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("agent CA certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !cert.IsCA {
		return nil, fmt.Errorf("agent CA certificate is invalid")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("agent CA private key PEM is invalid")
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse agent CA private key: %w", err)
	}
	key, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("agent CA private key must be ECDSA")
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("agent CA certificate and private key do not match")
	}
	if now == nil {
		now = time.Now
	}
	return &Signer{cert: cert, key: key, certPEM: append([]byte(nil), certPEM...), now: now}, nil
}

func (s *Signer) CACertificatePEM() string { return string(s.certPEM) }

func (s *Signer) SignCSR(csrPEM []byte, clusterID string, lifetime time.Duration) (Issued, error) {
	if s == nil || s.cert == nil || s.key == nil {
		return Issued{}, fmt.Errorf("agent CA signer is not configured")
	}
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return Issued{}, fmt.Errorf("cluster id is required")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return Issued{}, fmt.Errorf("CSR PEM is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return Issued{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err = csr.CheckSignature(); err != nil {
		return Issued{}, fmt.Errorf("CSR signature is invalid: %w", err)
	}
	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok {
		return Issued{}, fmt.Errorf("agent CSR public key must be ECDSA")
	}
	if lifetime <= 0 {
		lifetime = DefaultLifetime
	}
	if lifetime > 90*24*time.Hour {
		return Issued{}, fmt.Errorf("agent certificate lifetime cannot exceed 90 days")
	}
	now := s.now().UTC()
	serial, err := randomSerial()
	if err != nil {
		return Issued{}, err
	}
	uri, _ := url.Parse("spiffe://platform.4so.io/managed-cluster/" + url.PathEscape(clusterID))
	subject := "managed-cluster:" + clusterID
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject, Organization: []string{"4SO Platform Factory Agents"}},
		URIs:         []*url.URL{uri},
		NotBefore:    now.Add(-2 * time.Minute), NotAfter: now.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, s.cert, csr.PublicKey, s.key)
	if err != nil {
		return Issued{}, err
	}
	sum := sha256.Sum256(der)
	return Issued{
		CertificatePEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		CACertificatePEM: string(s.certPEM), SerialNumber: strings.ToLower(serial.Text(16)),
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]), Subject: subject,
		NotBefore: tpl.NotBefore, NotAfter: tpl.NotAfter,
	}, nil
}

func ClusterIDFromCertificate(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("client certificate is required")
	}
	const prefix = "spiffe://platform.4so.io/managed-cluster/"
	for _, uri := range cert.URIs {
		if strings.HasPrefix(uri.String(), prefix) {
			raw := strings.TrimPrefix(uri.String(), prefix)
			v, err := url.PathUnescape(raw)
			if err == nil && strings.TrimSpace(v) != "" {
				return v, nil
			}
		}
	}
	const cnPrefix = "managed-cluster:"
	if strings.HasPrefix(cert.Subject.CommonName, cnPrefix) {
		return strings.TrimPrefix(cert.Subject.CommonName, cnPrefix), nil
	}
	return "", fmt.Errorf("client certificate does not identify a managed cluster")
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}

func (s *Signer) VerifyClientCertificate(cert *x509.Certificate, intermediates []*x509.Certificate, now time.Time) error {
	if s == nil || s.cert == nil {
		return fmt.Errorf("agent CA signer is not configured")
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.cert)
	inter := x509.NewCertPool()
	for _, c := range intermediates {
		if c != nil {
			inter.AddCert(c)
		}
	}
	if now.IsZero() {
		now = s.now().UTC()
	}
	_, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now.UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func (s *Signer) IssueServerCertificate(serverName string, lifetime time.Duration) (certPEM, keyPEM []byte, notAfter time.Time, err error) {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return nil, nil, time.Time{}, fmt.Errorf("server name is required")
	}
	if s == nil || s.cert == nil || s.key == nil {
		return nil, nil, time.Time{}, fmt.Errorf("agent CA signer is not configured")
	}
	if lifetime <= 0 {
		lifetime = 365 * 24 * time.Hour
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	now := s.now().UTC()
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: serverName, Organization: []string{"4SO Platform Factory"}}, NotBefore: now.Add(-2 * time.Minute), NotAfter: now.Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(serverName); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{serverName}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, s.cert, &key.PublicKey, s.key)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), tpl.NotAfter, nil
}
