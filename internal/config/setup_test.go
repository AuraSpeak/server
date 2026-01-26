package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.yml")

	cfg := &Config{}
	cfg.Server.Port = "9090"
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Env = "prod"

	err := SaveConfig(cfg, configPath)
	require.NoError(t, err)

	// Check that file exists
	_, err = os.Stat(configPath)
	assert.NoError(t, err)

	// Load and check
	loadedCfg := &Config{}
	f, err := os.Open(configPath)
	require.NoError(t, err)
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(loadedCfg)
	require.NoError(t, err)

	assert.Equal(t, "9090", loadedCfg.Server.Port)
	assert.Equal(t, "127.0.0.1", loadedCfg.Server.Host)
	assert.Equal(t, "prod", loadedCfg.Server.Env)
}

func TestSaveConfig_WriteError(t *testing.T) {
	cfg := &Config{}
	configPath := "/nonexistent/path/test_config.yml"

	err := SaveConfig(cfg, configPath)
	assert.Error(t, err)
}

func TestParseStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"simple", "a,b,c", []string{"a", "b", "c"}},
		{"with spaces", "a, b, c", []string{"a", "b", "c"}},
		{"empty", "", []string{}},
		{"single", "a", []string{"a"}},
		{"with empty parts", "a,,b", []string{"a", "b"}},
		{"whitespace only", "   ,  ,  ", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStringSlice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		portStr string
		wantErr bool
	}{
		{"valid", "8080", false},
		{"min valid", "1", false},
		{"max valid", "65535", false},
		{"too small", "0", true},
		{"negative", "-1", true},
		{"too large", "65536", true},
		{"invalid format", "abc", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePort(tt.portStr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"valid IPv4", "127.0.0.1", false},
		{"valid IPv6", "::1", false},
		{"valid hostname", "localhost", false},
		{"valid hostname with domain", "example.com", false},
		{"empty", "", true},
		{"too long", string(make([]byte, 254)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHost(tt.host)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
