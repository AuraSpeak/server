// Package config provides interactive setup functionality.
package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

// Setup runs an interactive setup to create a server configuration.
// It prompts the user for all configuration values and saves the result to the given path.
func Setup(path string) (*Config, error) {
	fmt.Println("=== Server Configuration Setup ===")
	fmt.Println()

	cfg := &Config{}

	// Server base configuration
	fmt.Println("--- Server Configuration ---")
	cfg.Server.Port = promptString("Port", "8080")
	cfg.Server.Host = promptString("Host", "0.0.0.0")
	cfg.Server.Env = promptChoice("Environment (dev/prod)", []string{"dev", "prod"}, "dev")
	fmt.Println()

	// DTLS Certificates
	fmt.Println("--- DTLS Certificates ---")
	cfg.Server.DTLS.Certs.Mode = promptChoice("Certificate mode (self_signed/files)", []string{"self_signed", "files"}, "self_signed")

	if cfg.Server.DTLS.Certs.Mode == "files" {
		cfg.Server.DTLS.Certs.Path = promptString("Certificate path", "certs/")
		cfg.Server.DTLS.Certs.Cert = promptString("Certificate file", "server.crt")
		cfg.Server.DTLS.Certs.Key = promptString("Key file", "server.key")
		caInput := promptString("CA file (optional, press Enter to skip)", "")
		if caInput != "" {
			cfg.Server.DTLS.Certs.CA = caInput
		}
	}
	fmt.Println()

	// DTLS Security
	fmt.Println("--- DTLS Security ---")
	clientAuthChoices := []string{
		"no_client_cert",
		"request_client_cert",
		"require_any_client_cert",
		"verify_client_cert_if_given",
		"require_and_verify_client_cert",
	}
	cfg.Server.DTLS.Security.ClientAuth = promptChoice("Client authentication", clientAuthChoices, "no_client_cert")

	cipherSuitesInput := promptString("Cipher suites (comma-separated, optional, press Enter to skip)", "")
	if cipherSuitesInput != "" {
		cfg.Server.DTLS.Security.CipherSuites = parseStringSlice(cipherSuitesInput)
	}

	cfg.Server.DTLS.Security.ExtendedMasterSecret = promptChoice("Extended Master Secret (request/require/disable)", []string{"request", "require", "disable"}, "request")
	fmt.Println()

	// DTLS Tuning
	fmt.Println("--- DTLS Tuning ---")
	cfg.Server.DTLS.Tuning.MTU = promptInt("MTU", 1200)
	cfg.Server.DTLS.Tuning.ReplayProtectionWindow = promptInt("Replay Protection Window", 64)

	flightIntervalInput := promptString("Flight Interval (e.g., '1s', optional, press Enter to skip)", "")
	if flightIntervalInput != "" {
		cfg.Server.DTLS.Tuning.FlightInterval = flightIntervalInput
	}

	cfg.Server.DTLS.Tuning.InsecureSkipVerifyHello = promptBool("Insecure Skip Verify Hello (DoS risk, y/n)", false)
	fmt.Println()

	// Save configuration
	fmt.Printf("Saving configuration to %s...\n", path)
	if err := SaveConfig(cfg, path); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}
	fmt.Println("Configuration saved successfully!")
	fmt.Println()

	return cfg, nil
}

// SaveConfig saves a Config to a YAML file.
func SaveConfig(cfg *Config, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := yaml.NewEncoder(f)
	defer encoder.Close()
	if err := encoder.Encode(cfg); err != nil {
		return err
	}
	return nil
}

// promptString prompts for a string value with a default.
func promptString(prompt string, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)

	defaultText := ""
	if defaultVal != "" {
		defaultText = fmt.Sprintf(" [%s]", defaultVal)
	}
	fmt.Printf("%s%s: ", prompt, defaultText)

	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return defaultVal
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// promptInt prompts for an integer value with validation and a default.
func promptInt(prompt string, defaultVal int) int {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%s [%d]: ", prompt, defaultVal)

	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return defaultVal
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}

	val, err := strconv.Atoi(input)
	if err != nil {
		fmt.Printf("Invalid integer, using default %d\n", defaultVal)
		return defaultVal
	}
	return val
}

// promptChoice prompts for a choice from a list of options with a default.
func promptChoice(prompt string, choices []string, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)

	choicesText := strings.Join(choices, "/")
	fmt.Printf("%s (%s) [%s]: ", prompt, choicesText, defaultVal)

	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return defaultVal
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}

	// Check if input is a valid choice
	for _, choice := range choices {
		if strings.EqualFold(input, choice) {
			return choice
		}
	}

	fmt.Printf("Invalid choice, using default %s\n", defaultVal)
	return defaultVal
}

// promptBool prompts for a boolean value (y/n) with a default.
func promptBool(prompt string, defaultVal bool) bool {
	reader := bufio.NewReader(os.Stdin)

	defaultText := "n"
	if defaultVal {
		defaultText = "y"
	}
	fmt.Printf("%s [%s]: ", prompt, defaultText)

	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return defaultVal
	}

	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return defaultVal
	}

	return input == "y" || input == "yes"
}

// parseStringSlice parses a comma-separated string into a slice of strings.
func parseStringSlice(input string) []string {
	parts := strings.Split(input, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// validatePort validates a port number string.
func validatePort(portStr string) error {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port number: %w", err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

// validateHost validates a host string (IP address or hostname).
func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	// Try parsing as IP first
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	// If not an IP, assume it's a hostname (basic validation)
	if len(host) > 253 {
		return fmt.Errorf("hostname too long")
	}
	return nil
}
