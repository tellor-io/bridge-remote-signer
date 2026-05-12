package consensus

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/privval"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

func TestLoadCometFilePV_StateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.json")
	statePath := filepath.Join(dir, "state.json")
	privval.GenFilePV(keyPath, statePath).Save()

	pv1, err := LoadCometFilePV(keyPath, statePath)
	if err != nil {
		t.Fatalf("LoadCometFilePV error: %v", err)
	}
	lpv := NewLockedPrivValidator(pv1)
	addr, err := ValidatorAddressForHandler(lpv)
	if err != nil {
		t.Fatal(err)
	}
	h := ValidationRequestHandler(addr)
	chainID := "roundtrip"

	// Sign a vote to advance state
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	blockID := cmtproto.BlockID{
		Hash:          hash,
		PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash},
	}
	req := privvalproto.Message{
		Sum: &privvalproto.Message_SignVoteRequest{
			SignVoteRequest: &privvalproto.SignVoteRequest{
				ChainId: chainID,
				Vote: &cmtproto.Vote{
					Type:             cmtproto.PrevoteType,
					Height:           77,
					Round:            2,
					BlockID:          blockID,
					ValidatorAddress: addr,
					ValidatorIndex:   0,
				},
			},
		},
	}
	if _, err := h(lpv, req, chainID); err != nil {
		t.Fatalf("sign vote error: %v", err)
	}

	// Verify state file written
	b, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("state file is empty after signing")
	}

	// Reload and compare
	pv2, err := LoadCometFilePV(keyPath, statePath)
	if err != nil {
		t.Fatalf("reload LoadCometFilePV error: %v", err)
	}
	if pv1.LastSignState.Height != pv2.LastSignState.Height {
		t.Errorf("height mismatch: %d vs %d", pv1.LastSignState.Height, pv2.LastSignState.Height)
	}
	if pv1.LastSignState.Round != pv2.LastSignState.Round {
		t.Errorf("round mismatch: %d vs %d", pv1.LastSignState.Round, pv2.LastSignState.Round)
	}
	if pv1.LastSignState.Step != pv2.LastSignState.Step {
		t.Errorf("step mismatch: %d vs %d", pv1.LastSignState.Step, pv2.LastSignState.Step)
	}
}

func TestLoadCometFilePV_MissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadCometFilePV(
		filepath.Join(dir, "missing_key.json"),
		filepath.Join(dir, "state.json"),
	)
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestLoadCometFilePV_MissingStateFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.json")
	statePath := filepath.Join(dir, "state.json")
	privval.GenFilePV(keyPath, statePath).Save()

	// Remove the state file — LoadCometFilePV must succeed (new signer, no prior state)
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	pv, err := LoadCometFilePV(keyPath, statePath)
	if err != nil {
		t.Fatalf("expected success with no state file, got: %v", err)
	}
	if pv.LastSignState.Height != 0 {
		t.Errorf("expected height 0, got %d", pv.LastSignState.Height)
	}
}

func TestLoadCometFilePV_MalformedKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.json")
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(keyPath, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCometFilePV(keyPath, statePath)
	if err == nil {
		t.Fatal("expected error for malformed key file")
	}
}

func TestLoadCometFilePV_MalformedStateFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.json")
	statePath := filepath.Join(dir, "state.json")
	privval.GenFilePV(keyPath, statePath).Save()
	if err := os.WriteFile(statePath, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCometFilePV(keyPath, statePath)
	if err == nil {
		t.Fatal("expected error for malformed state file")
	}
}
