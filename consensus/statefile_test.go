package consensus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureStateFile_MissingWithoutInit_Refuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "priv_validator_state.json")
	err := EnsureStateFile(path, false)
	if err == nil {
		t.Fatal("expected error when state file is missing and --init not set, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected a 'not found' refusal, got: %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("state file must not be created without --init")
	}
}

func TestEnsureStateFile_MissingWithInit_Creates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "priv_validator_state.json")
	if err := EnsureStateFile(path, true); err != nil {
		t.Fatalf("expected --init to create the state file, got: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("state file should exist after --init: %v", err)
	}
	got := strings.TrimSpace(string(b))
	if got != `{"height":"0","round":0,"step":0}` {
		t.Fatalf("unexpected fresh state contents: %s", got)
	}
}

func TestEnsureStateFile_ExistsWithInit_Refuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "priv_validator_state.json")
	if err := os.WriteFile(path, []byte(`{"height":"42","round":0,"step":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := EnsureStateFile(path, true)
	if err == nil {
		t.Fatal("expected error when --init is used with an existing state file, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected an 'already exists' refusal, got: %v", err)
	}
	// The existing state must be left untouched.
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"height":"42"`) {
		t.Fatalf("existing state file must not be overwritten, got: %s", b)
	}
}

func TestEnsureStateFile_ExistsWithoutInit_OK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "priv_validator_state.json")
	if err := os.WriteFile(path, []byte(`{"height":"42","round":0,"step":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureStateFile(path, false); err != nil {
		t.Fatalf("normal start with an existing state file should succeed, got: %v", err)
	}
}
