// Package config defines the server configuration structure.
package config

// Config represents the complete server configuration loaded from YAML.
type Config struct {
	Server struct {
		Port string `yaml:"port,omitempty"`
		Host string `yaml:"host,omitempty"`
		Env  string `yaml:"env,omitempty"` // prod or dev; if nothing is set then prod
		DTLS struct {
			Certs struct {
				Mode string `yaml:"mode,omitempty"` // "self_signed" | "files"
				Path string `yaml:"path,omitempty"` // for mode=files
				Cert string `yaml:"cert,omitempty"`
				Key  string `yaml:"key,omitempty"`
				CA   string `yaml:"ca,omitempty"` // optional, for ClientCAs when client_auth requires it
			} `yaml:"certs"`
			Security struct {
				ClientAuth           string   `yaml:"client_auth,omitempty"`            // no_client_cert | request_client_cert | require_any_client_cert | verify_client_cert_if_given | require_and_verify_client_cert
				CipherSuites         []string `yaml:"cipher_suites,omitempty"`          // optional, nil/empty = Pion default
				ExtendedMasterSecret string   `yaml:"extended_master_secret,omitempty"` // request | require | disable
			} `yaml:"security"`
			Tuning struct {
				MTU                     int    `yaml:"mtu,omitempty"`                        // default 1200
				ReplayProtectionWindow  int    `yaml:"replay_protection_window,omitempty"`   // default 64
				FlightInterval          string `yaml:"flight_interval,omitempty"`            // e.g., "1s", optional
				InsecureSkipVerifyHello bool   `yaml:"insecure_skip_verify_hello,omitempty"` // DoS risk, only for special cases
			} `yaml:"tuning"`
		} `yaml:"dtls"`
	} `yaml:"server"`
}
