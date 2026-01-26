// Package debugui provides server configuration loading functionality
// exclusively for the debug-ui application.
//
// This package should NOT be used by other parts of the codebase.
// It exists solely to allow the debug-ui to access the server's internal
// configuration structure without violating Go's internal package restrictions.
package debugui

import (
	"github.com/auraspeak/server/internal/config"
)

// Config represents the server configuration.
// This is a type alias to the internal config.Config type.
type Config = config.Config

// LoadConfig loads the server configuration from "server_config.yml".
// If the file does not exist, it runs an interactive setup to create the configuration.
//
// This function is intended for use by the debug-ui application only.
// Other parts of the codebase should use the server package's configuration
// mechanisms directly.
func LoadConfig() *Config {
	return config.Load()
}
