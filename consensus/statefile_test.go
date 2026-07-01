package consensus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireStateFile_Missing_Refuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "priv_validator_state.json")
	err := RequireStateFile(path)
	if err == nil {
		t.Fatal("expected error when the state file is missing, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected a 'not found' refusal, got: %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("start must never create the state file")
	}
}

func TestRequireStateFile_Exists_OK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "priv_validator_state.json")
	if err := os.WriteFile(path, []byte(`{"height":"42","round":0,"step":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RequireStateFile(path); err != nil {
		t.Fatalf("start with an existing state file should succeed, got: %v", err)
	}
}

func TestInitStateFile_Missing_Creates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "priv_validator_state.json")
	if err := InitStateFile(path); err != nil {
		t.Fatalf("init-state should create the state file, got: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("state file should exist after init-state: %v", err)
	}
	if got := strings.TrimSpace(string(b)); got != `{"height":"0","round":0,"step":0}` {
		t.Fatalf("unexpected fresh state contents: %s", got)
	}
}

func TestInitStateFile_Exists_Refuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "priv_validator_state.json")
	if err := os.WriteFile(path, []byte(`{"height":"42","round":0,"step":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := InitStateFile(path)
	if err == nil {
		t.Fatal("expected error when init-state runs with an existing state file, got nil")
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
