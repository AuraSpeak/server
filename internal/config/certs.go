// Package config provides certificate generation functionality.
package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func generateSelfSigned() (tls.Certificate, *x509.Certificate, []byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, fmt.Errorf("serial: %w", err)
	}

	now := time.Now()
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "dev-dtls",
			Organization: []string{"local"},
		},
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // dev convenience

		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, fmt.Errorf("create cert: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, fmt.Errorf("parse cert: %w", err)
	}

	// PEM encode cert
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// PEM encode key (PKCS#8)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, fmt.Errorf("x509 key pair: %w", err)
	}
	tlsCert.Leaf = leaf

	return tlsCert, leaf, certPEM, keyPEM, nil
}

func writePEMFiles(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("mkdir cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return fmt.Errorf("mkdir key dir: %w", err)
	}

	// cert: world-readable is usually fine for dev; tighten if you want.
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	// key: restrict perms
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	return nil
}

// GenerateCertificates generates self-signed certificates based on config and writes them to file.
// Uses dtls.certs path, cert, key, ca for mode=files. Not used when dtls.certs.mode=self_signed.
func GenerateCertificates(cfg *Config) error {
	c := &cfg.Server.DTLS.Certs
	certPath := filepath.Join(c.Path, c.Cert)
	keyPath := filepath.Join(c.Path, c.Key)
	caPath := filepath.Join(c.Path, c.CA)

	// Check if certs already exist
	if _, errCert := os.Stat(certPath); errCert == nil {
		if _, errKey := os.Stat(keyPath); errKey == nil {
			if _, errCA := os.Stat(caPath); errCA == nil {
				// All files exist, skip generation
				return nil
			}
		}
	}

	// Generate self-signed certificate
	_, _, certPEM, keyPEM, err := generateSelfSigned()
	if err != nil {
		return fmt.Errorf("generate self-signed cert: %w", err)
	}

	// Write PEM files to the configured paths
	// For self-signed, the CA certificate is the same as the server certificate
	if err := writePEMFiles(certPath, keyPath, certPEM, keyPEM); err != nil {
		return fmt.Errorf("write pem files: %w", err)
	}

	// Write CA certificate (same as cert for self-signed)
	if err := os.MkdirAll(filepath.Dir(caPath), 0o755); err != nil {
		return fmt.Errorf("mkdir ca dir: %w", err)
	}
	if err := os.WriteFile(caPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write ca: %w", err)
	}

	return nil
}
