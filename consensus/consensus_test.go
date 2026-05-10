package consensus

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// newTestFilePV creates an in-memory FilePV for tests without touching disk.
func newTestFilePV(t *testing.T) *privval.FilePV {
	t.Helper()
	key := ed25519.GenPrivKey()
	pv := privval.NewFilePV(key, t.TempDir()+"/key.json", t.TempDir()+"/state.json")
	return pv
}

// ── LockedPrivValidator ──────────────────────────────────────────────────────

func TestLockedPrivValidator_GetPubKey(t *testing.T) {
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)

	pk, err := lpv.GetPubKey()
	if err != nil {
		t.Fatalf("GetPubKey() error: %v", err)
	}
	if pk == nil {
		t.Fatal("expected non-nil public key")
	}
	if len(pk.Address()) != crypto.AddressSize {
		t.Errorf("address length %d, want %d", len(pk.Address()), crypto.AddressSize)
	}
}

func TestLockedPrivValidator_ConcurrentAccess(t *testing.T) {
	// Two goroutines (simulating primary + backup nodes) call SignVote for the
	// SAME height/round/data concurrently — the LockedPrivValidator must
	// serialise access so FilePV can return the cached idempotent signature.
	// No panics or races must occur (run with -race to verify).
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)

	pk, err := lpv.GetPubKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := pk.Address()

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	blockID := cmtproto.BlockID{
		Hash:          hash,
		PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash},
	}

	// Both goroutines sign the exact same vote (same height/round/blockID).
	// FilePV is idempotent for identical data; both calls must succeed.
	var wg sync.WaitGroup
	var errCount atomic.Int64

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vote := &cmtproto.Vote{
				Type:             cmtproto.PrevoteType,
				Height:           1,
				Round:            0,
				BlockID:          blockID,
				ValidatorAddress: addr,
				ValidatorIndex:   0,
			}
			if err := lpv.SignVote("layertest-5", vote); err != nil {
				errCount.Add(1)
				t.Logf("SignVote err=%v", err)
			}
		}()
	}
	wg.Wait()
	if errCount.Load() > 0 {
		t.Errorf("%d SignVote calls failed", errCount.Load())
	}
}

// ── ValidationRequestHandler ─────────────────────────────────────────────────

func TestValidationRequestHandler_PubKeyRequest(t *testing.T) {
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)
	addr, err := ValidatorAddressForHandler(lpv)
	if err != nil {
		t.Fatal(err)
	}

	handler := ValidationRequestHandler(addr)
	req := privvalproto.Message{
		Sum: &privvalproto.Message_PubKeyRequest{
			PubKeyRequest: &privvalproto.PubKeyRequest{ChainId: "layertest-5"},
		},
	}
	resp, err := handler(lpv, req, "layertest-5")
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	pkResp := MustPubKeyResponse(&resp)
	if pkResp == nil {
		t.Fatal("expected PubKeyResponse")
	}
	if pkResp.Error != nil {
		t.Errorf("unexpected error in response: %v", pkResp.Error)
	}

	pk, err := PubKeyFromResponse(pkResp)
	if err != nil {
		t.Fatalf("PubKeyFromResponse: %v", err)
	}
	if !pk.Equals(pv.Key.PubKey) {
		t.Error("returned public key does not match signer key")
	}
}

func TestValidationRequestHandler_EmptyChainID(t *testing.T) {
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)
	addr, _ := ValidatorAddressForHandler(lpv)
	handler := ValidationRequestHandler(addr)

	req := privvalproto.Message{
		Sum: &privvalproto.Message_PubKeyRequest{
			PubKeyRequest: &privvalproto.PubKeyRequest{ChainId: ""},
		},
	}
	_, err := handler(lpv, req, "layertest-5")
	if err == nil {
		t.Error("expected error for empty chain_id, got nil")
	}
}

func TestValidationRequestHandler_NilVote(t *testing.T) {
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)
	addr, _ := ValidatorAddressForHandler(lpv)
	handler := ValidationRequestHandler(addr)

	req := privvalproto.Message{
		Sum: &privvalproto.Message_SignVoteRequest{
			SignVoteRequest: &privvalproto.SignVoteRequest{
				ChainId: "layertest-5",
				Vote:    nil,
			},
		},
	}
	_, err := handler(lpv, req, "layertest-5")
	if err == nil {
		t.Error("expected error for nil vote, got nil")
	}
}

func TestValidationRequestHandler_WrongValidatorAddress(t *testing.T) {
	// Double-signing prevention: request with a different validator address
	// must be rejected before reaching the signer.
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)
	addr, _ := ValidatorAddressForHandler(lpv)
	handler := ValidationRequestHandler(addr)

	// Build a vote with a different (wrong) address.
	wrongAddr := make([]byte, crypto.AddressSize)
	for i := range wrongAddr {
		wrongAddr[i] = 0xFF
	}
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	vote := &cmtproto.Vote{
		Type:             cmtproto.PrevoteType,
		Height:           1,
		Round:            0,
		BlockID:          goodBlockID(),
		ValidatorAddress: wrongAddr,
		ValidatorIndex:   0,
	}
	req := privvalproto.Message{
		Sum: &privvalproto.Message_SignVoteRequest{
			SignVoteRequest: &privvalproto.SignVoteRequest{
				ChainId: "layertest-5",
				Vote:    vote,
			},
		},
	}
	resp, err := handler(lpv, req, "layertest-5")
	if err == nil {
		t.Error("expected error for wrong validator address (double-sign guard), got nil")
	}
	voteResp := MustSignedVoteResponse(&resp)
	if voteResp == nil || voteResp.Error == nil {
		t.Error("expected RemoteSignerError in response for wrong address")
	}
}

func TestValidationRequestHandler_ExtensionOnNilPrecommit(t *testing.T) {
	// CometBFT v0.38 rule: vote extensions are only valid on non-nil Precommits.
	// Signing a nil-block precommit with an extension must be rejected.
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)
	addr, _ := ValidatorAddressForHandler(lpv)
	handler := ValidationRequestHandler(addr)

	vote := &cmtproto.Vote{
		Type:             cmtproto.PrecommitType,
		Height:           1,
		Round:            0,
		BlockID:          nilBlockID(), // nil block — extension forbidden
		ValidatorAddress: addr,
		ValidatorIndex:   0,
		Extension:        []byte("should-not-be-here"),
	}
	req := privvalproto.Message{
		Sum: &privvalproto.Message_SignVoteRequest{
			SignVoteRequest: &privvalproto.SignVoteRequest{
				ChainId: "layertest-5",
				Vote:    vote,
			},
		},
	}
	_, err := handler(lpv, req, "layertest-5")
	if err == nil {
		t.Error("expected error for extension on nil precommit, got nil")
	}
}

func TestValidationRequestHandler_NilProposal(t *testing.T) {
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)
	addr, _ := ValidatorAddressForHandler(lpv)
	handler := ValidationRequestHandler(addr)

	req := privvalproto.Message{
		Sum: &privvalproto.Message_SignProposalRequest{
			SignProposalRequest: &privvalproto.SignProposalRequest{
				ChainId:  "layertest-5",
				Proposal: nil,
			},
		},
	}
	_, err := handler(lpv, req, "layertest-5")
	if err == nil {
		t.Error("expected error for nil proposal, got nil")
	}
}
