package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// checkpointReplayGuard enforces a monotonic high-water mark on the bridge
// checkpoint validator_timestamp so a replayed (or out-of-order) checkpoint
// request can never be re-signed. The high-water value is persisted to a small
// file (atomically: temp-file + rename) so the guard survives restarts.
//
// If statePath is empty the guard keeps the high-water mark in memory only
// (used in tests and when no consensus state dir is configured).
type checkpointReplayGuard struct {
	mu        sync.Mutex
	statePath string
	highWater uint64
	loaded    bool
}

// newCheckpointReplayGuard creates a guard backed by statePath. If statePath is
// non-empty its current contents (if any) seed the high-water mark.
func newCheckpointReplayGuard(statePath string) (*checkpointReplayGuard, error) {
	g := &checkpointReplayGuard{statePath: statePath}
	if statePath == "" {
		g.loaded = true
		return g, nil
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			g.loaded = true
			return g, nil
		}
		return nil, fmt.Errorf("read checkpoint replay guard %q: %w", statePath, err)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse checkpoint replay guard %q: %w", statePath, err)
	}
	g.highWater = v
	g.loaded = true
	return g, nil
}

// CheckAndAdvance rejects ts if it is <= the persisted high-water mark, then
// atomically persists ts as the new high-water mark. Returns an error (and
// advances nothing) on replay/out-of-order or on a persistence failure — the
// caller must FAIL CLOSED and sign nothing if this returns non-nil.
func (g *checkpointReplayGuard) CheckAndAdvance(ts uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.loaded && ts <= g.highWater {
		return fmt.Errorf("replay guard: validator_timestamp %d is not greater than last signed %d", ts, g.highWater)
	}

	if g.statePath != "" {
		if err := writeUint64Atomic(g.statePath, ts); err != nil {
			return fmt.Errorf("persist checkpoint replay guard: %w", err)
		}
	}

	g.highWater = ts
	return nil
}

// writeUint64Atomic writes v to path atomically by writing a temp file in the
// same directory, fsyncing it, renaming it into place (overwriting), then
// fsyncing the parent directory. Unlike WriteNewFileAtomic this intentionally
// overwrites the previous value (the high-water mark advances).
func writeUint64Atomic(path string, v uint64) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %q: %w", dir, err)
	}

	f, err := os.CreateTemp(dir, ".ckpt-hw-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	if _, err := f.WriteString(strconv.FormatUint(v, 10)); err != nil {
		f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file to %q: %w", path, err)
	}

	return syncDirBestEffort(dir)
}

// syncDirBestEffort fsyncs dir so the rename is durable across a crash.
func syncDirBestEffort(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir %q for fsync: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir %q: %w", dir, err)
	}
	return nil
}
