package consensus

import (
	"strings"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// ── chain ID validation ──────────────────────────────────────────────────────

func TestValidateRequestChainID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid", "layertest-5", false},
		{"empty", "", true},
		{"exactly max", strings.Repeat("a", maxChainIDLen), false},
		{"over max", strings.Repeat("a", maxChainIDLen+1), true},
		{"contains NUL", "layer\x00test", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRequestChainID(tc.id)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateRequestChainID(%q) err=%v, wantErr=%v", tc.id, err, tc.wantErr)
			}
		})
	}
}

// ── vote validation ──────────────────────────────────────────────────────────

func goodBlockID() cmtproto.BlockID {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	return cmtproto.BlockID{
		Hash: hash,
		PartSetHeader: cmtproto.PartSetHeader{
			Total: 1,
			Hash:  hash,
		},
	}
}

func nilBlockID() cmtproto.BlockID {
	return cmtproto.BlockID{}
}

func TestValidateSignVoteRequest(t *testing.T) {
	validAddr := make([]byte, crypto.AddressSize)
	for i := range validAddr {
		validAddr[i] = byte(i + 1)
	}

	tests := []struct {
		name    string
		vote    *cmtproto.Vote
		addr    []byte
		wantErr bool
	}{
		{
			name: "valid prevote",
			vote: &cmtproto.Vote{
				Type:             cmtproto.PrevoteType,
				Height:           100,
				Round:            0,
				BlockID:          goodBlockID(),
				ValidatorAddress: validAddr,
				ValidatorIndex:   0,
			},
			addr: validAddr,
		},
		{
			name: "valid precommit with extension",
			vote: &cmtproto.Vote{
				Type:             cmtproto.PrecommitType,
				Height:           100,
				Round:            0,
				BlockID:          goodBlockID(),
				ValidatorAddress: validAddr,
				ValidatorIndex:   0,
				Extension:        []byte("some-extension-data"),
			},
			addr: validAddr,
		},
		{
			name: "valid nil precommit (no extension)",
			vote: &cmtproto.Vote{
				Type:             cmtproto.PrecommitType,
				Height:           100,
				Round:            0,
				BlockID:          nilBlockID(),
				ValidatorAddress: validAddr,
				ValidatorIndex:   0,
			},
			addr: validAddr,
		},
		{
			name:    "nil vote",
			vote:    nil,
			wantErr: true,
		},
		{
			name: "invalid vote type",
			vote: &cmtproto.Vote{
				Type:             cmtproto.SignedMsgType(99),
				Height:           100,
				ValidatorAddress: validAddr,
				ValidatorIndex:   0,
				BlockID:          goodBlockID(),
			},
			wantErr: true,
		},
		{
			name: "zero height",
			vote: &cmtproto.Vote{
				Type:             cmtproto.PrevoteType,
				Height:           0,
				ValidatorAddress: validAddr,
				ValidatorIndex:   0,
				BlockID:          goodBlockID(),
			},
			wantErr: true,
		},
		{
			name: "negative round",
			vote: &cmtproto.Vote{
				Type:             cmtproto.PrevoteType,
				Height:           1,
				Round:            -1,
				ValidatorAddress: validAddr,
				ValidatorIndex:   0,
				BlockID:          goodBlockID(),
			},
			wantErr: true,
		},
		{
			name: "negative validator index",
			vote: &cmtproto.Vote{
				Type:             cmtproto.PrevoteType,
				Height:           1,
				ValidatorAddress: validAddr,
				ValidatorIndex:   -1,
				BlockID:          goodBlockID(),
			},
			wantErr: true,
		},
		{
			name: "wrong validator address",
			vote: &cmtproto.Vote{
				Type:             cmtproto.PrevoteType,
				Height:           1,
				ValidatorAddress: make([]byte, crypto.AddressSize), // all zeros
				ValidatorIndex:   0,
				BlockID:          goodBlockID(),
			},
			addr:    validAddr,
			wantErr: true,
		},
		{
			// Double-signing prevention: extension on nil-block precommit is forbidden.
			name: "extension on nil precommit",
			vote: &cmtproto.Vote{
				Type:             cmtproto.PrecommitType,
				Height:           1,
				ValidatorAddress: validAddr,
				ValidatorIndex:   0,
				BlockID:          nilBlockID(),
				Extension:        []byte("bad"),
			},
			addr:    validAddr,
			wantErr: true,
		},
		{
			// Extension on prevote is forbidden.
			name: "extension on prevote",
			vote: &cmtproto.Vote{
				Type:             cmtproto.PrevoteType,
				Height:           1,
				ValidatorAddress: validAddr,
				ValidatorIndex:   0,
				BlockID:          goodBlockID(),
				Extension:        []byte("bad"),
			},
			addr:    validAddr,
			wantErr: true,
		},
		{
			// Extension signature on prevote is forbidden.
			name: "extension signature on prevote",
			vote: &cmtproto.Vote{
				Type:               cmtproto.PrevoteType,
				Height:             1,
				ValidatorAddress:   validAddr,
				ValidatorIndex:     0,
				BlockID:            goodBlockID(),
				ExtensionSignature: []byte("bad"),
			},
			addr:    validAddr,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSignVoteRequest(tc.vote, tc.addr)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateSignVoteRequest() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// ── proposal validation ──────────────────────────────────────────────────────

func TestValidateSignProposalRequest(t *testing.T) {
	tests := []struct {
		name     string
		proposal *cmtproto.Proposal
		wantErr  bool
	}{
		{
			name: "valid proposal",
			proposal: &cmtproto.Proposal{
				Type:     cmtproto.ProposalType,
				Height:   1,
				Round:    0,
				PolRound: -1,
				BlockID:  goodBlockID(),
			},
		},
		{
			name:     "nil proposal",
			proposal: nil,
			wantErr:  true,
		},
		{
			name: "wrong type",
			proposal: &cmtproto.Proposal{
				Type:    cmtproto.PrevoteType,
				Height:  1,
				BlockID: goodBlockID(),
			},
			wantErr: true,
		},
		{
			name: "negative height",
			proposal: &cmtproto.Proposal{
				Type:     cmtproto.ProposalType,
				Height:   -1,
				PolRound: -1,
				BlockID:  goodBlockID(),
			},
			wantErr: true,
		},
		{
			name: "negative round",
			proposal: &cmtproto.Proposal{
				Type:     cmtproto.ProposalType,
				Height:   1,
				Round:    -1,
				PolRound: -1,
				BlockID:  goodBlockID(),
			},
			wantErr: true,
		},
		{
			name: "invalid pol round",
			proposal: &cmtproto.Proposal{
				Type:     cmtproto.ProposalType,
				Height:   1,
				PolRound: -2,
				BlockID:  goodBlockID(),
			},
			wantErr: true,
		},
		{
			name: "incomplete block id",
			proposal: &cmtproto.Proposal{
				Type:     cmtproto.ProposalType,
				Height:   1,
				PolRound: -1,
				BlockID:  nilBlockID(),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSignProposalRequest(tc.proposal)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateSignProposalRequest() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
