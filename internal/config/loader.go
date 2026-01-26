// Package config provides configuration loading functionality.
package config

import (
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// Load loads the server configuration from "server_config.yml".
// If the file does not exist, it runs an interactive setup using
// `Setup` to create the configuration. The function returns a
// pointer to the decoded `Config`. For unrecoverable I/O errors it
// logs the error and exits the process.
func Load() *Config {
	const cfgPath = "server_config.yml"

	f, err := os.Open(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Infof("%s not found: starting interactive setup", cfgPath)
			cfg, setupErr := Setup(cfgPath)
			if setupErr != nil {
				log.WithError(setupErr).Error("Failed to create config via setup")
				os.Exit(1)
			}
			return cfg
		} else {
			log.WithError(err).Error("Cant read Config")
			os.Exit(1)
		}
	}
	defer f.Close()

	var config Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&config)
	if err != nil {
		log.WithError(err).Error("Cant decode yaml")
	}
	return &config
}

// WriteDefaultConfig writes a default server_config.yml to the given path.
func WriteDefaultConfig(path string) error {
	cfg := Config{}
	cfg.Server.Port = "8080"
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Env = "dev"

	cfg.Server.DTLS.Certs.Mode = "self_signed"
	cfg.Server.DTLS.Certs.Path = "certs/"
	cfg.Server.DTLS.Certs.Cert = "server.crt"
	cfg.Server.DTLS.Certs.Key = "server.key"
	cfg.Server.DTLS.Certs.CA = "ca.crt"

	cfg.Server.DTLS.Security.ClientAuth = "no_client_cert"
	cfg.Server.DTLS.Security.ExtendedMasterSecret = "request"

	cfg.Server.DTLS.Tuning.MTU = 1200
	cfg.Server.DTLS.Tuning.ReplayProtectionWindow = 64
	cfg.Server.DTLS.Tuning.InsecureSkipVerifyHello = false

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := yaml.NewEncoder(f)
	defer encoder.Close()
	if err := encoder.Encode(&cfg); err != nil {
		return err
	}
	return nil
}
