package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes body to a config.yaml in a temp dir, replacing {KEYRING}
// with a real (empty) keyring directory so the file-backend stat check passes.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	keyringDir := filepath.Join(dir, "keyring")
	if err := os.Mkdir(keyringDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(body, "{KEYRING}", keyringDir)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const bridgeOnlyBase = `
signer:
  backend: file
  keyring_dir: {KEYRING}
  key_name: test-key
tls:
  insecure: true
`

// A bridge-only config (no consensus section) with no explicit guard path must
// be rejected: the checkpoint replay guard would be memory-only and reset on
// restart.
func TestLoad_BridgeOnlyWithoutGuardPath_Errors(t *testing.T) {
	_, err := Load(writeConfig(t, bridgeOnlyBase))
	if err == nil || !strings.Contains(err.Error(), "checkpoint_guard_state_file") {
		t.Fatalf("want checkpoint_guard_state_file error, got: %v", err)
	}
}

func TestLoad_BridgeOnlyWithGuardPath_OK(t *testing.T) {
	cfg, err := Load(writeConfig(t, bridgeOnlyBase+`
server:
  checkpoint_guard_state_file: /data/bridge_checkpoint_state.json
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.CheckpointGuardStatePath(); got != "/data/bridge_checkpoint_state.json" {
		t.Fatalf("CheckpointGuardStatePath = %q, want explicit path", got)
	}
}

func TestLoad_BridgeOnlyCheckpointDisabled_OK(t *testing.T) {
	_, err := Load(writeConfig(t, bridgeOnlyBase+`
server:
  enabled_rpcs:
    sign_bridge_checkpoint: false
`))
	if err != nil {
		t.Fatalf("Load with sign_bridge_checkpoint disabled: %v", err)
	}
}

// With consensus signing configured, the guard path derives from the consensus
// state file's directory and no explicit setting is needed.
func TestLoad_ConsensusEnabled_GuardPathDerived_OK(t *testing.T) {
	cfg, err := Load(writeConfig(t, bridgeOnlyBase+`
chain_id: layertest-5
consensus:
  key_file: /keys/priv_validator_key.json
  state_file: /data/priv_validator_state.json
  targets: tcp://layer:26659
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := filepath.Join("/data", "bridge_checkpoint_state.json")
	if got := cfg.CheckpointGuardStatePath(); got != want {
		t.Fatalf("CheckpointGuardStatePath = %q, want %q", got, want)
	}
}
