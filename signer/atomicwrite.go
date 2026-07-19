package signer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// WriteNewFileAtomic writes data to path atomically and refuses to replace an existing file.
//
// It writes to a temp file in the same directory, chmods, fsyncs, hardlinks into place
// (which fails atomically if path already exists), then fsyncs the parent directory so the
// new entry survives a crash. The temp file is always cleaned up.
func WriteNewFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := validatePerm(perm); err != nil {
		return err
	}

	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, ".atomic-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	defer func() { _ = f.Close() }()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite %q", path)
		}
		return fmt.Errorf("link temp file to %q: %w", path, err)
	}

	return syncDir(dir)
}

func validatePerm(perm os.FileMode) error {
	if perm&^0o777 != 0 {
		return fmt.Errorf("perm %#o has bits outside 0o777 (no setuid/setgid/sticky); refusing", perm)
	}
	if perm&0o077 != 0 {
		return fmt.Errorf("perm %#o is accessible by group or others; refusing (use 0o600 for secrets)", perm)
	}
	return nil
}

// syncDir fsyncs dir so a recent link or rename is durable across a crash.
func syncDir(dir string) error {
	d, err := os.OpenFile(dir, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open dir %q for fsync: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir %q: %w", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("close dir %q: %w", dir, err)
	}
	return nil
}
