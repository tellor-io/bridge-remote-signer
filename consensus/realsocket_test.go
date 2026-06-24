package consensus

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// TestRealSocket_PrivvalHandshake_V038 is the off-mainnet proof that the
// CometBFT v0.38 pin fixes the privval mismatch that crashed the validator
// (signer was on v0.39.1, node on v0.38.17).
//
// It stands the signer's dial-client against CometBFT's OWN
// SignerListenerEndpoint — the exact privval server a layerd (CometBFT v0.38.17)
// node runs on its priv_validator_laddr — over a REAL TCP + SecretConnection,
// and drives the full consensus-signing path the validator uses every block:
//   - SecretConnection handshake
//   - GetPubKey over the wire
//   - SignVote (prevote + precommit)
//   - double-sign protection (same H/R/S, different block => rejected)
//
// If the wire protocols disagreed (the v0.39 vs v0.38 bug), the handshake or the
// first request would fail. Passing proves node<->signer privval compatibility.
func TestRealSocket_PrivvalHandshake_V038(t *testing.T) {
	const chainID = "tellor-1"
	logger := log.NewNopLogger()

	// ── node side: CometBFT SignerListenerEndpoint over a real TCP socket ──
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	nodeKey := ed25519.GenPrivKey()
	secretLn := privval.NewTCPListener(rawLn, nodeKey)
	endpoint := privval.NewSignerListenerEndpoint(logger, secretLn)

	// ── signer side: RunDialClient dials the node's listen address ──
	lpv, handler, addr := setupHandler(t)
	connKey := ed25519.GenPrivKey()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunDialClient(ctx, rawLn.Addr().String(), chainID, connKey, lpv, handler, nil, logger)

	// Start the node endpoint — completes the SecretConnection handshake with the
	// dialing signer. A protocol mismatch fails here.
	if err := endpoint.Start(); err != nil {
		t.Fatalf("SignerListenerEndpoint.Start (handshake failed): %v", err)
	}
	defer func() { _ = endpoint.Stop() }()

	// Give the dialer a moment to connect on first use.
	time.Sleep(50 * time.Millisecond)

	// SignerClient is CometBFT's PrivValidator over the listener endpoint — the
	// node's view of the remote signer. Construction pings the signer.
	sc, err := privval.NewSignerClient(endpoint, chainID)
	if err != nil {
		t.Fatalf("NewSignerClient (ping failed): %v", err)
	}

	// GetPubKey over the privval socket.
	pk, err := sc.GetPubKey()
	if err != nil {
		t.Fatalf("GetPubKey over privval socket: %v", err)
	}
	if !bytes.Equal(pk.Address(), addr) {
		t.Fatalf("pubkey address mismatch: got %x want %x", pk.Address(), addr)
	}

	// Sign a prevote, then the matching precommit — the per-block path.
	prevote := voteOf(cmtproto.PrevoteType, 100, 0, addr, blockIDOf(1))
	if err := sc.SignVote(chainID, prevote); err != nil {
		t.Fatalf("SignVote prevote over socket: %v", err)
	}
	if len(prevote.Signature) == 0 {
		t.Fatal("prevote signature empty")
	}
	precommit := voteOf(cmtproto.PrecommitType, 100, 0, addr, blockIDOf(1))
	if err := sc.SignVote(chainID, precommit); err != nil {
		t.Fatalf("SignVote precommit over socket: %v", err)
	}
	if len(precommit.Signature) == 0 {
		t.Fatal("precommit signature empty")
	}

	// Double-sign protection: same height/round/step, different block => reject.
	conflicting := voteOf(cmtproto.PrecommitType, 100, 0, addr, blockIDOf(2))
	if err := sc.SignVote(chainID, conflicting); err == nil {
		t.Fatal("expected double-sign rejection for conflicting precommit at same H/R/S")
	}
}
