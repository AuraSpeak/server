package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCertificates_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{}
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = tmpDir
	cfg.Server.DTLS.Certs.Cert = "server.crt"
	cfg.Server.DTLS.Certs.Key = "server.key"
	cfg.Server.DTLS.Certs.CA = "ca.crt"

	// Create already existing files
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")
	caPath := filepath.Join(tmpDir, "ca.crt")

	err := os.WriteFile(certPath, []byte("existing cert"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, []byte("existing key"), 0600)
	require.NoError(t, err)
	err = os.WriteFile(caPath, []byte("existing ca"), 0644)
	require.NoError(t, err)

	// GenerateCertificates should be a no-op
	err = GenerateCertificates(cfg)
	assert.NoError(t, err)

	// Files should be unchanged
	certData, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, "existing cert", string(certData))
}

func TestGenerateCertificates_NormalGeneration(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{}
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = tmpDir
	cfg.Server.DTLS.Certs.Cert = "server.crt"
	cfg.Server.DTLS.Certs.Key = "server.key"
	cfg.Server.DTLS.Certs.CA = "ca.crt"

	err := GenerateCertificates(cfg)
	require.NoError(t, err)

	// Check that files were created
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")
	caPath := filepath.Join(tmpDir, "ca.crt")

	_, err = os.Stat(certPath)
	assert.NoError(t, err)
	_, err = os.Stat(keyPath)
	assert.NoError(t, err)
	_, err = os.Stat(caPath)
	assert.NoError(t, err)

	// Check permissions (key should be 0600)
	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm())
}

func TestGenerateCertificates_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")

	cfg := &Config{}
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = subDir
	cfg.Server.DTLS.Certs.Cert = "server.crt"
	cfg.Server.DTLS.Certs.Key = "server.key"
	cfg.Server.DTLS.Certs.CA = "ca.crt"

	err := GenerateCertificates(cfg)
	require.NoError(t, err)

	// Directory should have been created
	_, err = os.Stat(subDir)
	assert.NoError(t, err)
}

func TestGenerateCertificates_PartialExists(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{}
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = tmpDir
	cfg.Server.DTLS.Certs.Cert = "server.crt"
	cfg.Server.DTLS.Certs.Key = "server.key"
	cfg.Server.DTLS.Certs.CA = "ca.crt"

	// Create only cert, not key and ca
	certPath := filepath.Join(tmpDir, "server.crt")
	err := os.WriteFile(certPath, []byte("existing cert"), 0644)
	require.NoError(t, err)

	// GenerateCertificates should still generate
	err = GenerateCertificates(cfg)
	require.NoError(t, err)

	// All files should exist (cert was overwritten)
	_, err = os.Stat(certPath)
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, "server.key"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, "ca.crt"))
	assert.NoError(t, err)
}

func TestGenerateCertificates_InvalidConfig(t *testing.T) {
	// nil Config should lead to panic
	assert.Panics(t, func() {
		_ = GenerateCertificates(nil)
	})

	// Empty paths - use t.TempDir() to ensure files are not created in the current directory
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldDir)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	cfg := &Config{}
	cfg.Server.DTLS.Certs.Mode = "files"
	cfg.Server.DTLS.Certs.Path = "" // Empty path = current directory (now tmpDir)
	cfg.Server.DTLS.Certs.Cert = "server.crt"
	cfg.Server.DTLS.Certs.Key = "server.key"
	cfg.Server.DTLS.Certs.CA = "ca.crt"

	err = GenerateCertificates(cfg)
	// Should work, since paths are relative
	// Files will now be created in tmpDir, which is automatically cleaned up
	_ = err
}
