// Package dtls provides DTLS configuration building from server config.
package dtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/auraspeak/server/internal/config"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

var (
	cipherSuiteMap = map[string]dtls.CipherSuiteID{
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM":        dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8":      dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_PSK_WITH_AES_128_CCM":                dtls.TLS_PSK_WITH_AES_128_CCM,
		"TLS_PSK_WITH_AES_128_CCM_8":              dtls.TLS_PSK_WITH_AES_128_CCM_8,
		"TLS_PSK_WITH_AES_256_CCM_8":              dtls.TLS_PSK_WITH_AES_256_CCM_8,
		"TLS_PSK_WITH_AES_128_GCM_SHA256":         dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		"TLS_PSK_WITH_AES_128_CBC_SHA256":         dtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256":   dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	}

	clientAuthMap = map[string]dtls.ClientAuthType{
		"no_client_cert":                 dtls.NoClientCert,
		"request_client_cert":            dtls.RequestClientCert,
		"require_any_client_cert":        dtls.RequireAnyClientCert,
		"verify_client_cert_if_given":    dtls.VerifyClientCertIfGiven,
		"require_and_verify_client_cert": dtls.RequireAndVerifyClientCert,
	}

	extendedMasterSecretMap = map[string]dtls.ExtendedMasterSecretType{
		"request": dtls.RequestExtendedMasterSecret,
		"require": dtls.RequireExtendedMasterSecret,
		"disable": dtls.DisableExtendedMasterSecret,
	}
)

func clientAuthRequiresClientCAs(t dtls.ClientAuthType) bool {
	return t != dtls.NoClientCert
}

// NewDTLSConfig builds a Pion DTLS Config from Config.
// If dtls.certs.mode is empty: env=="dev" -> "self_signed", else "files".
// cfg must not be nil; for a default config the caller must pass a minimal ServerConfig with mode=self_signed.
func NewDTLSConfig(cfg *config.Config) (*dtls.Config, error) {
	d := &cfg.Server.DTLS
	mode := d.Certs.Mode
	if mode == "" {
		if cfg.Server.Env == "dev" {
			mode = "self_signed"
		} else {
			mode = "files"
		}
	}

	var certs []tls.Certificate
	var clientCAs *x509.CertPool

	switch mode {
	case "self_signed":
		cert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, fmt.Errorf("dtls.certs: self_signed: %w", err)
		}
		certs = []tls.Certificate{cert}
	case "files":
		if d.Certs.Path == "" || d.Certs.Cert == "" || d.Certs.Key == "" {
			return nil, fmt.Errorf("dtls.certs: mode=files requires path, cert and key")
		}
		cert, err := tls.LoadX509KeyPair(
			filepath.Join(d.Certs.Path, d.Certs.Cert),
			filepath.Join(d.Certs.Path, d.Certs.Key),
		)
		if err != nil {
			return nil, fmt.Errorf("dtls.certs: load keypair: %w", err)
		}
		certs = []tls.Certificate{cert}

		clientAuth := resolveClientAuth(d.Security.ClientAuth)
		if clientAuthRequiresClientCAs(clientAuth) {
			if d.Certs.CA == "" {
				return nil, fmt.Errorf("dtls.certs: client_auth %q requires ca", d.Security.ClientAuth)
			}
			pem, err := os.ReadFile(filepath.Join(d.Certs.Path, d.Certs.CA))
			if err != nil {
				return nil, fmt.Errorf("dtls.certs: read ca: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("dtls.certs: failed to append ca")
			}
			clientCAs = pool
		}
	default:
		return nil, fmt.Errorf("dtls.certs: unknown mode %q", mode)
	}

	clientAuth := resolveClientAuth(d.Security.ClientAuth)
	if mode == "self_signed" && clientAuthRequiresClientCAs(clientAuth) {
		return nil, fmt.Errorf("dtls.certs: in self_signed mode client_auth must be no_client_cert; use mode=files with ca for client verification")
	}

	cipherSuites, err := resolveCipherSuites(d.Security.CipherSuites)
	if err != nil {
		return nil, err
	}

	ems := resolveExtendedMasterSecret(d.Security.ExtendedMasterSecret)

	mtu := d.Tuning.MTU
	if mtu <= 0 {
		mtu = 1200
	}
	rpw := d.Tuning.ReplayProtectionWindow
	if rpw <= 0 {
		rpw = 64
	}

	var flightInterval time.Duration
	if d.Tuning.FlightInterval != "" {
		flightInterval, err = time.ParseDuration(d.Tuning.FlightInterval)
		if err != nil {
			return nil, fmt.Errorf("dtls.tuning: invalid flight_interval %q: %w", d.Tuning.FlightInterval, err)
		}
	}

	p := parsedDTLS{
		clientAuth:              clientAuth,
		cipherSuites:            cipherSuites,
		extendedMasterSecret:    ems,
		mtu:                     mtu,
		replayProtectionWindow:  rpw,
		flightInterval:          flightInterval,
		insecureSkipVerifyHello: d.Tuning.InsecureSkipVerifyHello,
	}
	return dtlsConfigFromParsed(p, certs, clientCAs)
}

type parsedDTLS struct {
	clientAuth              dtls.ClientAuthType
	cipherSuites            []dtls.CipherSuiteID
	extendedMasterSecret    dtls.ExtendedMasterSecretType
	mtu                     int
	replayProtectionWindow  int
	flightInterval          time.Duration
	insecureSkipVerifyHello bool
}

func dtlsConfigFromParsed(p parsedDTLS, certs []tls.Certificate, clientCAs *x509.CertPool) (*dtls.Config, error) {
	out := &dtls.Config{
		Certificates:            certs,
		ClientAuth:              p.clientAuth,
		CipherSuites:            p.cipherSuites,
		ExtendedMasterSecret:    p.extendedMasterSecret,
		MTU:                     p.mtu,
		ReplayProtectionWindow:  p.replayProtectionWindow,
		InsecureSkipVerifyHello: p.insecureSkipVerifyHello,
		ClientCAs:               clientCAs,
	}
	if p.flightInterval > 0 {
		out.FlightInterval = p.flightInterval
	}
	return out, nil
}

func resolveClientAuth(s string) dtls.ClientAuthType {
	if s == "" {
		return dtls.NoClientCert
	}
	if v, ok := clientAuthMap[s]; ok {
		return v
	}
	return dtls.NoClientCert
}

func resolveCipherSuites(ids []string) ([]dtls.CipherSuiteID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	out := make([]dtls.CipherSuiteID, 0, len(ids))
	for _, id := range ids {
		v, ok := cipherSuiteMap[id]
		if !ok {
			return nil, fmt.Errorf("dtls.security: unknown cipher_suite %q", id)
		}
		out = append(out, v)
	}
	return out, nil
}

func resolveExtendedMasterSecret(s string) dtls.ExtendedMasterSecretType {
	if s == "" {
		return dtls.RequestExtendedMasterSecret
	}
	if v, ok := extendedMasterSecretMap[s]; ok {
		return v
	}
	return dtls.RequestExtendedMasterSecret
}
