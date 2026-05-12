package signer

import (
	"os"
	"path/filepath"
	"testing"
)

// ── WriteNewFileAtomic ────────────────────────────────────────────────────────

func TestWriteNewFileAtomic_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	data := []byte("test-key-data")

	if err := WriteNewFileAtomic(path, data, 0600); err != nil {
		t.Fatalf("WriteNewFileAtomic error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back error: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}
}

func TestWriteNewFileAtomic_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	if err := WriteNewFileAtomic(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("expected perm 0600, got %o", got)
	}
}

func TestWriteNewFileAtomic_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.key")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}

	err := WriteNewFileAtomic(path, []byte("new"), 0600)
	if err == nil {
		t.Fatal("expected error when file already exists")
	}

	// Original content must be unchanged
	got, _ := os.ReadFile(path)
	if string(got) != "original" {
		t.Errorf("original file was modified: %q", got)
	}
}

func TestWriteNewFileAtomic_NoTempFileLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")

	if err := WriteNewFileAtomic(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected exactly 1 file, found: %v", names)
	}
}

// ── validatePerm ─────────────────────────────────────────────────────────────

func TestValidatePerm_Valid(t *testing.T) {
	if err := validatePerm(0600); err != nil {
		t.Errorf("0600 should be valid: %v", err)
	}
	if err := validatePerm(0400); err != nil {
		t.Errorf("0400 should be valid: %v", err)
	}
}

func TestValidatePerm_GroupReadable(t *testing.T) {
	if err := validatePerm(0640); err == nil {
		t.Error("0640 should be rejected (group-readable)")
	}
}

func TestValidatePerm_WorldReadable(t *testing.T) {
	if err := validatePerm(0604); err == nil {
		t.Error("0604 should be rejected (world-readable)")
	}
}

func TestValidatePerm_SetuidBit(t *testing.T) {
	if err := validatePerm(0o4600); err == nil {
		t.Error("setuid bit should be rejected")
	}
}
