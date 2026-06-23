package consensus

import (
	"fmt"
	"os"
)

// freshStateJSON is the zero last-sign state CometBFT expects for a brand-new
// signer (height encoded as a string, matching cometbft's JSON, so LoadCometFilePV
// parses it back to height 0).
const freshStateJSON = `{"height":"0","round":0,"step":0}` + "\n"

// EnsureStateFile enforces the consensus state-file safety policy before the
// signer starts signing. The state file (priv_validator_state.json) is the
// double-sign guard: starting without it, or clobbering it, can make the signer
// sign a conflicting block at a height it already signed and get the validator
// tombstoned. The four cases:
//
//   - missing + init=false : refuse to start (a deleted or un-mounted state file
//     must never silently fresh-start the signer).
//   - exists  + init=true  : refuse to start (--init must not overwrite a real
//     last-sign state).
//   - missing + init=true  : create a fresh zero state file and continue.
//   - exists  + init=false : normal start.
func EnsureStateFile(stateFilePath string, init bool) error {
	info, statErr := os.Stat(stateFilePath)
	exists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("stat state file %s: %w", stateFilePath, statErr)
	}
	if exists && info.IsDir() {
		return fmt.Errorf("state file path %s is a directory", stateFilePath)
	}

	switch {
	case init && exists:
		return fmt.Errorf("state file %s already exists: --init cannot be used in conjunction with an existing state file", stateFilePath)
	case init && !exists:
		if err := os.WriteFile(stateFilePath, []byte(freshStateJSON), 0o600); err != nil {
			return fmt.Errorf("create state file %s: %w", stateFilePath, err)
		}
		return nil
	case !init && !exists:
		return fmt.Errorf("state file %s not found: refusing to start without a last-sign state; pass --init only when bootstrapping a brand-new signer", stateFilePath)
	default: // !init && exists
		return nil
	}
}
