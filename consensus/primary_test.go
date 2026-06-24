package consensus

import (
	"testing"
	"time"
)

func TestPrimaryArbiter(t *testing.T) {
	a := NewPrimaryArbiter(time.Minute, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	if !a.Acquire("nodeA") {
		t.Fatal("first node should become primary")
	}
	if a.Primary() != "nodeA" {
		t.Fatalf("primary = %q, want nodeA", a.Primary())
	}
	if !a.Acquire("nodeA") {
		t.Fatal("primary should always re-acquire")
	}
	if a.Acquire("nodeB") {
		t.Fatal("non-primary refused while primary is fresh")
	}

	// Within the timeout, still refused.
	a.now = func() time.Time { return base.Add(30 * time.Second) }
	if a.Acquire("nodeB") {
		t.Fatal("non-primary refused within timeout")
	}
	// Primary keeps signing -> refreshes the idle timer.
	if !a.Acquire("nodeA") {
		t.Fatal("primary re-acquire")
	}

	// Primary idle past the timeout -> nodeB takes over.
	a.now = func() time.Time { return base.Add(30*time.Second + time.Minute + time.Second) }
	if !a.Acquire("nodeB") {
		t.Fatal("non-primary should take over after primary idle past timeout")
	}
	if a.Primary() != "nodeB" {
		t.Fatalf("primary = %q, want nodeB after failover", a.Primary())
	}
	if a.Acquire("nodeA") {
		t.Fatal("old primary refused while new primary is fresh")
	}
}
