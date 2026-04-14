package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tellor-io/bridge-remote-signer/signer"
	"gopkg.in/yaml.v3"
)

// Backend identifies which signing backend to use.
type Backend string

const (
	BackendFile        Backend = "file"
	BackendFortanixDSM Backend = "fortanixdsm"
	BackendYubiHSM     Backend = "yubihsm"
)

// Config is the top-level configuration for bridge-signer.
// Loaded once at startup from a YAML file.
type Config struct {
	Signer SignerConfig `yaml:"signer"`
	Server ServerConfig `yaml:"server"`
	TLS    TLSConfig    `yaml:"tls"`
	Log    LogConfig    `yaml:"logging"`
}

// SignerConfig controls which backend holds the private key.
type SignerConfig struct {
	// Backend selects the signing backend: "file" or "fortanixdsm".
	Backend Backend `yaml:"backend"`

	// KeyPath is the path to the hex-encoded secp256k1 private key file.
	// Required when Backend == "file".
	KeyPath string `yaml:"key_path"`

	// --- FortanixDSM backend ---
	DSMAPIEndpoint string `yaml:"dsm_api_endpoint"`
	DSMAPIKey      string `yaml:"dsm_api_key"`
	DSMKeyID       string `yaml:"dsm_key_id"`
	DSMKeyName     string `yaml:"dsm_key_name"`

	// --- YubiHSM backend ---
	// Adapter: "usb" for direct USB (default)
	YubiHSMAdapter       signer.AdapterType `yaml:"yubihsm_adapter"`
	YubiHSMConnectorAddr string             `yaml:"yubihsm_connector_addr"`
	// Auth key ID. TMKMS convention: 1=admin, 2=operator, 3=auditor, 4=validator (sign-only).
	YubiHSMAuthKeyID    int    `yaml:"yubihsm_auth_key_id"`
	YubiHSMPassword     string `yaml:"yubihsm_password"`
	YubiHSMPasswordFile string `yaml:"yubihsm_password_file"`
	YubiHSMKeyID        int    `yaml:"yubihsm_key_id"`
	YubiHSMSerialNumber string `yaml:"yubihsm_serial_number"`
}

func (c *SignerConfig) ToMap() map[string]any {
	return map[string]any{
		"key_path":               c.KeyPath,
		"dsm_api_endpoint":       c.DSMAPIEndpoint,
		"dsm_api_key":            c.DSMAPIKey,
		"dsm_key_id":             c.DSMKeyID,
		"dsm_key_name":           c.DSMKeyName,
		"yubihsm_adapter":        string(c.YubiHSMAdapter),
		"yubihsm_connector_addr": c.YubiHSMConnectorAddr,
		"yubihsm_auth_key_id":    c.YubiHSMAuthKeyID,
		"yubihsm_password":       c.YubiHSMPassword,
		"yubihsm_password_file":  c.YubiHSMPasswordFile,
		"yubihsm_key_id":         c.YubiHSMKeyID,
		"yubihsm_serial_number":  c.YubiHSMSerialNumber,
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
}

// validate checks that all required fields are present and consistent.
func (c *Config) validate() error {
	// Signer
	switch c.Signer.Backend {
	case BackendFile:
		if c.Signer.KeyPath == "" {
			return errors.New("signer.key_path is required when backend is \"file\"")
		}
		if _, err := os.Stat(c.Signer.KeyPath); err != nil {
			return fmt.Errorf("signer.key_path %q: %w", c.Signer.KeyPath, err)
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
	case BackendYubiHSM:
		if c.Signer.YubiHSMKeyID == 0 {
			return errors.New("signer.yubihsm_key_id is required when backend is \"yubihsm\"")
		}
		if c.Signer.YubiHSMPassword == "" && c.Signer.YubiHSMPasswordFile == "" {
			return errors.New("signer.yubihsm_password or signer.yubihsm_password_file is required when backend is \"yubihsm\"")
		}
		if c.Signer.YubiHSMPasswordFile != "" {
			if _, err := os.Stat(c.Signer.YubiHSMPasswordFile); err != nil {
				return fmt.Errorf("signer.yubihsm_password_file %q: %w", c.Signer.YubiHSMPasswordFile, err)
			}
		}
		if c.Signer.YubiHSMAdapter == "http" && c.Signer.YubiHSMConnectorAddr == "" {
			return errors.New("signer.yubihsm_connector_addr is required when yubihsm_adapter is \"http\"")
		}
	case "":
		return errors.New("signer.backend is required (\"file\", \"fortanixdsm\", or \"yubihsm\")")
	default:
		return fmt.Errorf("signer.backend %q is not valid (must be \"file\", \"fortanixdsm\", or \"yubihsm\")", c.Signer.Backend)
	}

	// Server
	if c.Server.ListenAddr == "" {
		return errors.New("server.listen_addr is required")
	}
	if c.Server.RequestTimeout <= 0 {
		return errors.New("server.request_timeout must be positive")
	}

	if c.TLS.CACert == "" {
		return errors.New("tls.ca_cert is required")
	}
	if c.TLS.ServerCert == "" {
		return errors.New("tls.server_cert is required")
	}
	if c.TLS.ServerKey == "" {
		return errors.New("tls.server_key is required")
	}
	for _, path := range []string{c.TLS.CACert, c.TLS.ServerCert, c.TLS.ServerKey} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("tls file %q: %w", path, err)
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

	return nil
}
