package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Backend identifies which signing backend to use.
type Backend string

const (
	BackendFile        Backend = "file"
	BackendFortanixDSM Backend = "fortanixdsm"
)

// Config is the top-level configuration for bridge-signer.
// Loaded once at startup from a YAML file.
type Config struct {
	Consensus ConsensusConfig `yaml:"consensus"`
	Signer    SignerConfig    `yaml:"signer"`
	Server    ServerConfig    `yaml:"server"`
	TLS       TLSConfig       `yaml:"tls"`
	Log       LogConfig       `yaml:"logging"`
}

// ConsensusConfig controls the CometBFT privval TCP signer.
type ConsensusConfig struct {
	ChainID     string `yaml:"chain_id"`
	KeyFile     string `yaml:"key_file"`
	StateFile   string `yaml:"state_file"`
	ConnKeyFile string `yaml:"conn_key_file"`
	Targets     string `yaml:"targets"`
}

// Enabled returns true when consensus signing is configured.
func (c *ConsensusConfig) Enabled() bool {
	return c.KeyFile != ""
}

// SignerConfig controls which backend holds the private key.
type SignerConfig struct {
	// Backend selects the signing backend: "file" or "fortanixdsm".
	Backend Backend `yaml:"backend"`

	// --- File backend ---
	KeyringDir    string `yaml:"keyring_dir"`
	KeyName       string `yaml:"key_name"`
	PasswordFile  string `yaml:"password_file"`

	// --- FortanixDSM backend ---
	DSMAPIEndpoint string `yaml:"dsm_api_endpoint"`
	DSMAPIKey      string `yaml:"dsm_api_key"`
	DSMKeyID       string `yaml:"dsm_key_id"`
	DSMKeyName     string `yaml:"dsm_key_name"`
}

func (c *SignerConfig) ToMap() map[string]any {
	return map[string]any{
		"keyring_dir":      c.KeyringDir,
		"key_name":         c.KeyName,
		"password_file":    c.PasswordFile,
		"dsm_api_endpoint": c.DSMAPIEndpoint,
		"dsm_api_key":      c.DSMAPIKey,
		"dsm_key_id":       c.DSMKeyID,
		"dsm_key_name":     c.DSMKeyName,
	}
}

// ServerConfig controls the gRPC server.
type ServerConfig struct {
	// ListenAddr is the address the gRPC server listens on.
	// Example: "0.0.0.0:9191"
	ListenAddr string `yaml:"listen_addr"`

	// HealthAddr is the address the HTTP health check server listens on.
	// Example: "0.0.0.0:9192"
	HealthAddr string `yaml:"health_addr"`

	// RequestTimeout is the max time allowed for a single Sign or
	// GetOperatorAddress RPC call. Prevents a slow signing backend
	// from hanging the validator's vote extension deadline.
	// Default: 2s
	RequestTimeout time.Duration `yaml:"request_timeout"`

	// Default: 1MB
	MaxRecvMsgSize int `yaml:"max_recv_msg_size"`
}

// TLSConfig holds paths to the mTLS certificate material.
type TLSConfig struct {
	// Insecure disables TLS entirely. Safe to use inside a private Docker network.
	Insecure bool `yaml:"insecure"`

	// CACert is the path to the CA certificate used to verify client certs.
	CACert string `yaml:"ca_cert"`

	// ServerCert is the path to the sidecar's TLS certificate.
	ServerCert string `yaml:"server_cert"`

	// ServerKey is the path to the sidecar's TLS private key.
	ServerKey string `yaml:"server_key"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	// Default: "info"
	Level string `yaml:"level"`

	// Default: "json"
	Format string `yaml:"format"`
}

// Load reads and validates a Config from a YAML file at path.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config path must not be empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("cannot parse config file %q: %w", path, err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// applyDefaults fills in sensible defaults for optional fields.
func (c *Config) applyDefaults() {
	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = "0.0.0.0:9191"
	}
	if c.Server.HealthAddr == "" {
		c.Server.HealthAddr = "0.0.0.0:9192"
	}
	if c.Server.RequestTimeout == 0 {
		c.Server.RequestTimeout = 2 * time.Second
	}
	if c.Server.MaxRecvMsgSize == 0 {
		c.Server.MaxRecvMsgSize = 1024 * 1024 // 1MB
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}

	//Consensus defaults
	if c.Consensus.Enabled() {
		if c.Consensus.StateFile == "" {
			c.Consensus.StateFile = "/data/priv_validator_state.json"
		}
		if c.Consensus.ConnKeyFile == "" {
			c.Consensus.ConnKeyFile = "/data/connection.key"
		}
		if c.Consensus.Targets == "" {
			c.Consensus.Targets = "tcp://layer:26659,tcp://layer-backup:26659"
		}
	}
}

// validate checks that all required fields are present and consistent.
func (c *Config) validate() error {
	// Signer
	switch c.Signer.Backend {
	case BackendFile:
		if c.Signer.KeyringDir == "" {
			return errors.New("signer.keyring_dir is required when backend is \"file\"")
		}
		if _, err := os.Stat(c.Signer.KeyringDir); err != nil {
			return fmt.Errorf("signer.keyring_dir %q: %w", c.Signer.KeyringDir, err)
		}
		if c.Signer.KeyName == "" {
			return errors.New("signer.key_name is required when backend is \"file\"")
		}
	case BackendFortanixDSM:
		if c.Signer.DSMAPIEndpoint == "" {
			return errors.New("signer.dsm_api_endpoint is required when backend is \"fortanixdsm\"")
		}
		if c.Signer.DSMAPIKey == "" {
			return errors.New("signer.dsm_api_key is required when backend is \"fortanixdsm\"")
		}
		if c.Signer.DSMKeyID == "" && c.Signer.DSMKeyName == "" {
			return errors.New("signer.dsm_key_id or signer.dsm_key_name is required when backend is \"fortanixdsm\"")
		}
	case "":
		return errors.New("signer.backend is required (\"file\", \"fortanixdsm\")")
	default:
		return fmt.Errorf("signer.backend %q is not valid (must be \"file\", \"fortanixdsm\")", c.Signer.Backend)
	}

	// Server
	if c.Server.ListenAddr == "" {
		return errors.New("server.listen_addr is required")
	}
	if c.Server.RequestTimeout <= 0 {
		return errors.New("server.request_timeout must be positive")
	}

	if !c.TLS.Insecure {
		if c.TLS.CACert == "" {
			return errors.New("tls.ca_cert is required (or set tls.insecure: true)")
		}
		if c.TLS.ServerCert == "" {
			return errors.New("tls.server_cert is required (or set tls.insecure: true)")
		}
		if c.TLS.ServerKey == "" {
			return errors.New("tls.server_key is required (or set tls.insecure: true)")
		}
		for _, path := range []string{c.TLS.CACert, c.TLS.ServerCert, c.TLS.ServerKey} {
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("tls file %q: %w", path, err)
			}
		}
	}

	// Log
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level %q is not valid (debug|info|warn|error)", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("logging.format %q is not valid (json|text)", c.Log.Format)
	}

	if c.Consensus.Enabled() {
		if c.Consensus.ChainID == "" {
			return errors.New("consensus.chain_id is required when consensus.key_file is set")
		}
		if c.Consensus.StateFile == "" {
			return errors.New("consensus.state_file is required")
		}
		if c.Consensus.Targets == "" {
			return errors.New("consensus.targets is required")
		}
	}

	return nil
}
