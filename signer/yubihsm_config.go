package signer

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// AdapterType selects how to communicate with the YubiHSM2.
type AdapterType string

const (
	// AdapterUSB connects directly to the YubiHSM2 over USB via libyubihsm.
	// No yubihsm-connector daemon needed. Requires libyubihsm + libusb.
	AdapterUSB AdapterType = "usb"

	// AdapterHTTP connects via the yubihsm-connector daemon over HTTP.
	AdapterHTTP AdapterType = "http"
)

// YubiHSMConfig holds connection and authentication details for a YubiHSM2 device.
//
// https://github.com/iqlusioninc/tmkms/blob/main/README.yubihsm.md
// Follows TMKMS conventions:
//   - Adapter selects USB or HTTP connectivity
//   - Auth key IDs map to TMKMS roles (1=admin, 2=operator, 3=auditor, 4=validator)
//   - Password can be inline or loaded from a file
//   - Serial number narrows to a specific device when multiple are attached
type YubiHSMConfig struct {
	// Adapter selects the connection mode: "usb" or "http".
	// Default: "usb"
	Adapter AdapterType `yaml:"adapter"`

	// ConnectorAddr is the address of the yubihsm-connector daemon.
	// Required when Adapter == "http". Example: "localhost:12345"
	ConnectorAddr string `yaml:"connector_addr"`

	// AuthKeyID is the ID of the authentication key on the device.
	// TMKMS convention:
	//   0x0001 = admin (full access)
	//   0x0002 = operator (key gen, backup, audit)
	//   0x0003 = auditor (view audit log)
	//   0x0004 = validator (sign only)
	// Default: 1
	AuthKeyID int `yaml:"auth_key_id"`

	// Password is the password for the auth key (inline).
	Password string `yaml:"password"`

	// PasswordFile is the path to a file containing the auth key password.
	// The file should contain only the password with optional trailing whitespace.
	// Takes precedence over Password if both are set.
	PasswordFile string `yaml:"password_file"`

	// KeyID is the object ID of the secp256k1 signing key on the device.
	// This is the key that will be used for signing vote extensions.
	KeyID int `yaml:"key_id"`

	// SerialNumber optionally identifies a specific YubiHSM2 device when
	// multiple devices are connected via USB.
	// Example: "0123456789"
	// Only applies when Adapter == "usb". Leave empty to use any available device.
	SerialNumber string `yaml:"serial_number"`
}

// Validate checks that the config has all required fields.
func (c *YubiHSMConfig) Validate() error {
	if c.KeyID == 0 {
		return errors.New("yubihsm_key_id is required")
	}

	if c.Password == "" && c.PasswordFile == "" {
		return errors.New("either yubihsm_password or yubihsm_password_file is required")
	}

	switch c.Adapter {
	case AdapterHTTP:
		if c.ConnectorAddr == "" {
			return errors.New("yubihsm_connector_addr is required when adapter is \"http\"")
		}
	case AdapterUSB, "":
		// USB mode doesn't need connector.
	default:
		return fmt.Errorf("yubihsm adapter %q is not valid (must be \"usb\" or \"http\")", c.Adapter)
	}

	return nil
}

// ResolvePassword loads the password from file if configured, otherwise returns inline.
func (c *YubiHSMConfig) ResolvePassword() (string, error) {
	if c.PasswordFile != "" {
		data, err := os.ReadFile(c.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("cannot read password file %q: %w", c.PasswordFile, err)
		}
		return strings.TrimRight(string(data), "\n\r \t"), nil
	}
	return c.Password, nil
}

// ConnectorURL builds the libyubihsm connector URL based on adapter type.
func (c *YubiHSMConfig) ConnectorURL() string {
	switch c.Adapter {
	case AdapterHTTP:
		return "http://" + c.ConnectorAddr
	case AdapterUSB, "":
		if c.SerialNumber != "" {
			return "yhusb://serial=" + c.SerialNumber
		}
		return "yhusb://"
	default:
		return "yhusb://"
	}
}

// ParseYubiHSMConfig extracts a YubiHSMConfig from a raw config map.
// Used by the backend factory to parse YAML config into the typed struct.
func ParseYubiHSMConfig(raw map[string]interface{}) (YubiHSMConfig, error) {
	var cfg YubiHSMConfig

	if v, ok := raw["yubihsm_adapter"].(string); ok {
		cfg.Adapter = AdapterType(v)
	}
	if v, ok := raw["yubihsm_connector_addr"].(string); ok {
		cfg.ConnectorAddr = v
	}
	if v, ok := raw["yubihsm_auth_key_id"].(int); ok {
		cfg.AuthKeyID = v
	}
	if v, ok := raw["yubihsm_password"].(string); ok {
		cfg.Password = v
	}
	if v, ok := raw["yubihsm_password_file"].(string); ok {
		cfg.PasswordFile = v
	}
	if v, ok := raw["yubihsm_key_id"].(int); ok {
		cfg.KeyID = v
	}
	if v, ok := raw["yubihsm_serial_number"].(string); ok {
		cfg.SerialNumber = v
	}

	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid yubihsm config: %w", err)
	}

	return cfg, nil
}
