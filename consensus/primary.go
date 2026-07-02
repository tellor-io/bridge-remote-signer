package consensus

import (
	"sync"
	"time"

	"github.com/cometbft/cometbft/libs/log"
)

// PrimaryArbiter enforces active-passive consensus signing across nodes that
// share one validator key. Each dial target (its address / IP) is an id; only
// the current "primary" id may have its vote/proposal requests signed. If the
// primary sends no sign request within the failover timeout, the next id to
// request takes over.
//
// This stops two active nodes from racing the signer (which otherwise shows up
// as step-regression / conflicting-data rejections and the occasional missed
// block). The priv_validator_state high-water-mark check remains the ultimate
// double-sign backstop; this is an additional, earlier gate.
type PrimaryArbiter struct {
	timeout time.Duration
	logger  log.Logger

	mu      sync.Mutex
	primary string
	lastReq time.Time

	now func() time.Time // overridable in tests
}

// NewPrimaryArbiter returns an arbiter that fails over to another node after the
// primary has been idle for timeout. timeout must be > 0.
func NewPrimaryArbiter(timeout time.Duration, logger log.Logger) *PrimaryArbiter {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	return &PrimaryArbiter{timeout: timeout, logger: logger, now: time.Now}
}

// Acquire reports whether id may sign now. The current primary always may (and
// refreshes the idle timer); another id may take over only when there is no
// primary yet or the current primary has been idle longer than the timeout.
func (a *PrimaryArbiter) Acquire(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	switch {
	case a.primary == id:
		a.lastReq = now
		return true
	case a.primary == "" || now.Sub(a.lastReq) > a.timeout:
		prev := a.primary
		a.primary = id
		a.lastReq = now
		if prev == "" {
			a.logger.Info("consensus primary signer elected", "primary", id)
			return true
		}
		a.logger.Info("consensus primary signer failed over", "from", prev, "to", id, "after_idle", a.timeout.String())
		return true
	default:
		return false
	}
}

// Primary returns the current primary id ("" if none elected yet).
func (a *PrimaryArbiter) Primary() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.primary
}
