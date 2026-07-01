package consensus

import (
	"fmt"
	"os"
)

// freshStateJSON is the zero last-sign state CometBFT expects for a brand-new
// signer (height encoded as a string, matching cometbft's JSON, so LoadCometFilePV
// parses it back to height 0).
const freshStateJSON = `{"height":"0","round":0,"step":0}` + "\n"

// RequireStateFile checks that the consensus state file (priv_validator_state.json)
// exists before the signer starts. The state file is the double-sign high-water-mark;
// starting without it could make the signer sign a conflicting block at a height it
// already signed and get the validator tombstoned. `start` never creates the file, so a
// deleted or un-mounted state file fails closed here instead of silently fresh-starting.
// Bootstrap a brand-new signer once with the `init-state` command.
func RequireStateFile(stateFilePath string) error {
	info, err := os.Stat(stateFilePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("state file %s not found: refusing to start without a last-sign state; bootstrap a new signer once with 'init-state'", stateFilePath)
	}
	if err != nil {
		return fmt.Errorf("stat state file %s: %w", stateFilePath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("state file path %s is a directory", stateFilePath)
	}
	return nil
}

// InitStateFile creates a fresh zero last-sign state file for a brand-new signer. It
// refuses if one already exists so bootstrapping can never overwrite a real last-sign
// state (double-sign risk). This is a one-shot bootstrap step, kept separate from `start`
// so a run command that restarts repeatedly can never create or reset the state file.
func InitStateFile(stateFilePath string) error {
	info, err := os.Stat(stateFilePath)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("state file path %s is a directory", stateFilePath)
		}
		return fmt.Errorf("state file %s already exists: refusing to overwrite an existing last-sign state", stateFilePath)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat state file %s: %w", stateFilePath, err)
	}
	if err := os.WriteFile(stateFilePath, []byte(freshStateJSON), 0o600); err != nil {
		return fmt.Errorf("create state file %s: %w", stateFilePath, err)
	}
	return nil
}
