package consensus

import (
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

func hash32(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b + byte(i)
	}
	return h
}

func blockIDOf(b byte) cmtproto.BlockID {
	h := hash32(b)
	return cmtproto.BlockID{Hash: h, PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: h}}
}

func newFilePVAtPath(t *testing.T, dir string) *privval.FilePV {
	t.Helper()
	keyFile := filepath.Join(dir, "key.json")
	stateFile := filepath.Join(dir, "state.json")
	pv := privval.NewFilePV(ed25519.GenPrivKey(), keyFile, stateFile)
	pv.Save()
	return pv
}

func reloadFilePV(t *testing.T, dir string) *privval.FilePV {
	t.Helper()
	keyFile := filepath.Join(dir, "key.json")
	stateFile := filepath.Join(dir, "state.json")
	return privval.LoadFilePV(keyFile, stateFile)
}

func voteOf(typ cmtproto.SignedMsgType, height int64, round int32, addr []byte, bid cmtproto.BlockID) *cmtproto.Vote {
	return &cmtproto.Vote{
		Type:             typ,
		Height:           height,
		Round:            round,
		BlockID:          bid,
		ValidatorAddress: addr,
		ValidatorIndex:   0,
	}
}

func TestDoubleSign_PrecommitConflictRejected(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))
	addr := mustAddr(t, lpv)

	if err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 100, 0, addr, blockIDOf(1))); err != nil {
		t.Fatalf("first precommit sign failed: %v", err)
	}
	err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 100, 0, addr, blockIDOf(2)))
	if err == nil {
		t.Fatal("DOUBLE SIGN: second conflicting precommit at same H/R was signed")
	}
}
func TestDoubleSign_NilThenBlockRejected(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))
	addr := mustAddr(t, lpv)

	// Precommit a real block first.
	if err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 200, 0, addr, blockIDOf(7))); err != nil {
		t.Fatalf("first sign (block) failed: %v", err)
	}
	// Now a nil precommit at the same H/R conflicts.
	nilVote := voteOf(cmtproto.PrecommitType, 200, 0, addr, cmtproto.BlockID{})
	if err := lpv.SignVote("tellor-1", nilVote); err == nil {
		t.Fatal("DOUBLE SIGN: nil precommit accepted after block precommit at same H/R")
	}
}
func TestDoubleSign_LowerRoundAfterHigherRejected(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))
	addr := mustAddr(t, lpv)

	if err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 300, 5, addr, blockIDOf(3))); err != nil {
		t.Fatalf("sign at round 5 failed: %v", err)
	}
	err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 300, 2, addr, blockIDOf(4)))
	if err == nil {
		t.Fatal("HRS regression: vote at lower round accepted after higher round")
	}
}
func TestDoubleSign_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	// First instance signs a block at height 400.
	pv1 := newFilePVAtPath(t, dir)
	lpv1 := NewLockedPrivValidator(pv1)
	addr := mustAddr(t, lpv1)
	if err := lpv1.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 400, 0, addr, blockIDOf(9))); err != nil {
		t.Fatalf("first instance sign failed: %v", err)
	}

	// "Restart": reload FilePV from the same key+state files.
	pv2 := reloadFilePV(t, dir)
	lpv2 := NewLockedPrivValidator(pv2)

	// Conflicting block at the same height must be rejected by the persisted state.
	err := lpv2.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 400, 0, addr, blockIDOf(10)))
	if err == nil {
		t.Fatal("DOUBLE SIGN ACROSS RESTART: reloaded signer signed a conflicting block at the same height")
	}
}
func TestDoubleSign_ProposalConflictRejected(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))

	propA := &cmtproto.Proposal{Type: cmtproto.ProposalType, Height: 500, Round: 0, PolRound: -1, BlockID: blockIDOf(11)}
	propB := &cmtproto.Proposal{Type: cmtproto.ProposalType, Height: 500, Round: 0, PolRound: -1, BlockID: blockIDOf(12)}

	if err := lpv.SignProposal("tellor-1", propA); err != nil {
		t.Fatalf("first proposal sign failed: %v", err)
	}
	if err := lpv.SignProposal("tellor-1", propB); err == nil {
		t.Fatal("DOUBLE SIGN: second conflicting proposal at same H/R was signed")
	}
}

func TestDoubleSign_DifferentChainSameHRSConflict(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))
	addr := mustAddr(t, lpv)

	if err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 600, 0, addr, blockIDOf(13))); err != nil {
		t.Fatalf("first sign failed: %v", err)
	}
	// Same HRS, different block, different chain id — FilePV tracks HRS regardless
	// of chain id, so this conflicting vote must be rejected.
	err := lpv.SignVote("some-other-chain", voteOf(cmtproto.PrecommitType, 600, 0, addr, blockIDOf(14)))
	if err == nil {
		t.Fatal("DOUBLE SIGN: conflicting vote at same HRS accepted under a different chain id")
	}
}

func mustAddr(t *testing.T, lpv *LockedPrivValidator) []byte {
	t.Helper()
	pk, err := lpv.GetPubKey()
	if err != nil {
		t.Fatalf("GetPubKey: %v", err)
	}
	return pk.Address()
}
