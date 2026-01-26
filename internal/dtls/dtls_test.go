package dtls

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/auraspeak/server/internal/config"
	"github.com/pion/dtls/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDTLSConfig_SelfSigned(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.NotEmpty(t, dtlsCfg.Certificates)
}

func TestNewDTLSConfig_FilesMode(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate certificates
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = tmpDir
	cfg.Server.DTLS.Certs.Cert = "server.crt"
	cfg.Server.DTLS.Certs.Key = "server.key"
	cfg.Server.DTLS.Certs.CA = "ca.crt"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"

	err := config.GenerateCertificates(cfg)
	require.NoError(t, err)

	// Check that files exist
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")

	// Check that files exist
	_, err = os.Stat(certPath)
	require.NoError(t, err)
	_, err = os.Stat(keyPath)
	require.NoError(t, err)

	// Teste NewDTLSConfig mit files mode
	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.NotEmpty(t, dtlsCfg.Certificates)
}

func TestNewDTLSConfig_FilesMode_MissingFiles(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{}
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = tmpDir
	cfg.Server.DTLS.Certs.Cert = "nonexistent.crt"
	cfg.Server.DTLS.Certs.Key = "nonexistent.key"

	dtlsCfg, err := NewDTLSConfig(cfg)
	assert.Error(t, err)
	assert.Nil(t, dtlsCfg)
	assert.Contains(t, err.Error(), "load keypair")
}

func TestNewDTLSConfig_InvalidMode(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.DTLS.Certs.Mode = "invalid_mode"

	dtlsCfg, err := NewDTLSConfig(cfg)
	assert.Error(t, err)
	assert.Nil(t, dtlsCfg)
	assert.Contains(t, err.Error(), "unknown mode")
}

func TestNewDTLSConfig_EmptyMode_Dev(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = ""
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"

	// Should default to self_signed
	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
}

func TestNewDTLSConfig_EmptyMode_Prod(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "prod"
	cfg.Server.DTLS.Certs.Mode = ""

	// Should default to files, but files are missing
	dtlsCfg, err := NewDTLSConfig(cfg)
	assert.Error(t, err)
	assert.Nil(t, dtlsCfg)
}

func TestNewDTLSConfig_ClientAuth_NoClientCert(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.Equal(t, dtls.NoClientCert, dtlsCfg.ClientAuth)
}

func TestNewDTLSConfig_ClientAuth_RequiresCA(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = tmpDir
	cfg.Server.DTLS.Certs.Cert = "server.crt"
	cfg.Server.DTLS.Certs.Key = "server.key"
	cfg.Server.DTLS.Certs.CA = "ca.crt"
	cfg.Server.DTLS.Security.ClientAuth = "require_and_verify_client_cert"

	// Generate certificates (including CA)
	err := config.GenerateCertificates(cfg)
	require.NoError(t, err)

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.NotNil(t, dtlsCfg.ClientCAs)
}

func TestNewDTLSConfig_ClientAuth_MissingCA(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = tmpDir
	cfg.Server.DTLS.Certs.Cert = "server.crt"
	cfg.Server.DTLS.Certs.Key = "server.key"
	cfg.Server.DTLS.Certs.CA = "" // Keine CA gesetzt
	cfg.Server.DTLS.Security.ClientAuth = "require_and_verify_client_cert"

	// Generate certificates (without CA - GenerateCertificates will not write CA if empty)
	cfg.Server.DTLS.Certs.CA = "ca.crt"
	err := config.GenerateCertificates(cfg)
	require.NoError(t, err)

	// Remove CA from config for test
	cfg.Server.DTLS.Certs.CA = ""
	dtlsCfg, err := NewDTLSConfig(cfg)
	assert.Error(t, err)
	assert.Nil(t, dtlsCfg)
	assert.Contains(t, err.Error(), "requires ca")
}

func TestNewDTLSConfig_SelfSigned_WithClientAuth(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "require_and_verify_client_cert"

	dtlsCfg, err := NewDTLSConfig(cfg)
	assert.Error(t, err)
	assert.Nil(t, dtlsCfg)
	assert.Contains(t, err.Error(), "self_signed mode client_auth must be no_client_cert")
}

func TestNewDTLSConfig_CipherSuites_Valid(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Security.CipherSuites = []string{
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.NotEmpty(t, dtlsCfg.CipherSuites)
}

func TestNewDTLSConfig_CipherSuites_Invalid(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Security.CipherSuites = []string{"INVALID_CIPHER_SUITE"}

	dtlsCfg, err := NewDTLSConfig(cfg)
	assert.Error(t, err)
	assert.Nil(t, dtlsCfg)
	assert.Contains(t, err.Error(), "unknown cipher_suite")
}

func TestNewDTLSConfig_CipherSuites_Empty(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Security.CipherSuites = []string{}

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	// Empty list should result in nil (Pion default)
	assert.Nil(t, dtlsCfg.CipherSuites)
}

func TestNewDTLSConfig_ExtendedMasterSecret(t *testing.T) {
	tests := []struct {
		name     string
		ems      string
		expected dtls.ExtendedMasterSecretType
	}{
		{"request", "request", dtls.RequestExtendedMasterSecret},
		{"require", "require", dtls.RequireExtendedMasterSecret},
		{"disable", "disable", dtls.DisableExtendedMasterSecret},
		{"empty", "", dtls.RequestExtendedMasterSecret},
		{"invalid", "invalid", dtls.RequestExtendedMasterSecret}, // default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Server.Env = "dev"
			cfg.Server.DTLS.Certs.Mode = "self_signed"
			cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
			cfg.Server.DTLS.Security.ExtendedMasterSecret = tt.ems

			dtlsCfg, err := NewDTLSConfig(cfg)
			require.NoError(t, err)
			require.NotNil(t, dtlsCfg)
			assert.Equal(t, tt.expected, dtlsCfg.ExtendedMasterSecret)
		})
	}
}

func TestNewDTLSConfig_MTU_Default(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Tuning.MTU = 0

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.Equal(t, 1200, dtlsCfg.MTU)
}

func TestNewDTLSConfig_MTU_Custom(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Tuning.MTU = 1500

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.Equal(t, 1500, dtlsCfg.MTU)
}

func TestNewDTLSConfig_ReplayProtectionWindow_Default(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Tuning.ReplayProtectionWindow = 0

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.Equal(t, 64, dtlsCfg.ReplayProtectionWindow)
}

func TestNewDTLSConfig_ReplayProtectionWindow_Custom(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Tuning.ReplayProtectionWindow = 128

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.Equal(t, 128, dtlsCfg.ReplayProtectionWindow)
}

func TestNewDTLSConfig_FlightInterval_Valid(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Tuning.FlightInterval = "1s"

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.Equal(t, time.Second, dtlsCfg.FlightInterval)
}

func TestNewDTLSConfig_FlightInterval_Invalid(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Tuning.FlightInterval = "invalid"

	dtlsCfg, err := NewDTLSConfig(cfg)
	assert.Error(t, err)
	assert.Nil(t, dtlsCfg)
	assert.Contains(t, err.Error(), "invalid flight_interval")
}

func TestNewDTLSConfig_FlightInterval_Empty(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Tuning.FlightInterval = ""

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.Equal(t, time.Duration(0), dtlsCfg.FlightInterval)
}

func TestNewDTLSConfig_InsecureSkipVerifyHello(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Env = "dev"
	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Tuning.InsecureSkipVerifyHello = true

	dtlsCfg, err := NewDTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, dtlsCfg)
	assert.True(t, dtlsCfg.InsecureSkipVerifyHello)
}

func TestNewDTLSConfig_MissingPathCertKey(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = ""
	cfg.Server.DTLS.Certs.Cert = ""
	cfg.Server.DTLS.Certs.Key = ""

	dtlsCfg, err := NewDTLSConfig(cfg)
	assert.Error(t, err)
	assert.Nil(t, dtlsCfg)
	assert.Contains(t, err.Error(), "requires path, cert and key")
}
