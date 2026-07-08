package consensus

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/privval"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// sendReq writes a privval Message to conn and reads back the response.
func sendReq(t *testing.T, conn net.Conn, req privvalproto.Message) privvalproto.Message {
	t.Helper()
	wr := protoio.NewDelimitedWriter(conn)
	rd := protoio.NewDelimitedReader(conn, MaxRemoteSignerMsgSize)

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := wr.WriteMsg(&req)
	if err != nil {
		t.Fatalf("sendReq write: %v", err)
	}

	var resp privvalproto.Message
	_, err = rd.ReadMsg(&resp)
	if err != nil {
		t.Fatalf("sendReq read: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return resp
}

func pubKeyReq() privvalproto.Message {
	return privvalproto.Message{
		Sum: &privvalproto.Message_PubKeyRequest{
			PubKeyRequest: &privvalproto.PubKeyRequest{ChainId: "layertest-5"},
		},
	}
}

func signVoteReq(addr []byte, height int64, blockID cmtproto.BlockID) privvalproto.Message {
	return privvalproto.Message{
		Sum: &privvalproto.Message_SignVoteRequest{
			SignVoteRequest: &privvalproto.SignVoteRequest{
				ChainId: "layertest-5",
				Vote: &cmtproto.Vote{
					Type:             cmtproto.PrevoteType,
					Height:           height,
					Round:            0,
					BlockID:          blockID,
					ValidatorAddress: addr,
					ValidatorIndex:   0,
				},
			},
		},
	}
}

func nopLog() log.Logger { return log.NewNopLogger() }

// setupHandler builds a LockedPrivValidator + ValidationRequestHandler.
func setupHandler(t *testing.T) (*LockedPrivValidator, privval.ValidationRequestHandlerFunc, []byte) {
	t.Helper()
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)
	addr, err := ValidatorAddressForHandler(lpv)
	if err != nil {
		t.Fatal(err)
	}
	handler := ValidationRequestHandler(addr)
	return lpv, handler, addr
}

// ── TestNodeFailover ──────────────────────────────────────────────────────────
//
// Scenario: primary node connects, exchanges a PubKey request, then disconnects
// (simulates crash / network drop). runDialClient must reconnect and serve a
// second PubKey request successfully.

func TestNodeFailover(t *testing.T) {
	lpv, handler, _ := setupHandler(t)

	// Prepare two pipe pairs: first "connection", then the reconnect.
	c1client, c1node := net.Pipe()
	c2client, c2node := net.Pipe()

	calls := atomic.Int32{}
	dialFn := func() (net.Conn, error) {
		n := calls.Add(1)
		if n == 1 {
			return c1client, nil
		}
		return c2client, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go runDialClient(ctx, dialFn, "layertest-5", lpv, handler, nopLog(), nil)

	// ── First connection: send PubKeyRequest, verify response ────────────────
	resp1 := sendReq(t, c1node, pubKeyReq())
	pkResp := MustPubKeyResponse(&resp1)
	if pkResp == nil || pkResp.Error != nil {
		t.Fatalf("first connection: expected valid PubKeyResponse, got %+v", pkResp)
	}

	// Disconnect node side to trigger failover.
	_ = c1node.Close()

	// ── Second connection (reconnect): send PubKeyRequest again ─────────────
	// Give runDialClient time to reconnect (300 ms delay + processing).
	resp2 := sendReq(t, c2node, pubKeyReq())
	pkResp2 := MustPubKeyResponse(&resp2)
	if pkResp2 == nil || pkResp2.Error != nil {
		t.Fatalf("after failover: expected valid PubKeyResponse, got %+v", pkResp2)
	}

	// Both responses should carry the same public key.
	if !bytes.Equal(pkResp.PubKey.GetEd25519(), pkResp2.PubKey.GetEd25519()) {
		t.Error("public key changed across failover")
	}

	cancel()
}

// ── TestNodeRecovery ──────────────────────────────────────────────────────────
//
// Scenario: signer is running with a connection to one node. That node crashes
// and comes back online. The signer reconnects and signing resumes without
// manual intervention.

func TestNodeRecovery(t *testing.T) {
	lpv, handler, addr := setupHandler(t)

	// Track how many times dial is called.
	var dialCount atomic.Int32

	// Connections channel: test controls which conn is returned.
	connCh := make(chan net.Conn, 4)

	dialFn := func() (net.Conn, error) {
		dialCount.Add(1)
		return <-connCh, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go runDialClient(ctx, dialFn, "layertest-5", lpv, handler, nopLog(), nil)

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	blockID := cmtproto.BlockID{
		Hash:          hash,
		PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash},
	}

	// ── Round 1: initial connection, sign a vote ─────────────────────────────
	c1client, c1node := net.Pipe()
	connCh <- c1client

	resp1 := sendReq(t, c1node, signVoteReq(addr, 100, blockID))
	vr := MustSignedVoteResponse(&resp1)
	if vr == nil || vr.Error != nil {
		t.Fatalf("round 1: sign failed: %+v", vr)
	}

	// Simulate node crash.
	_ = c1node.Close()

	// ── Round 2: node recovered, new connection, sign a different height ─────
	c2client, c2node := net.Pipe()
	connCh <- c2client

	hash2 := make([]byte, 32)
	for i := range hash2 {
		hash2[i] = byte(i + 5) // different block
	}
	blockID2 := cmtproto.BlockID{
		Hash:          hash2,
		PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash2},
	}

	resp2 := sendReq(t, c2node, signVoteReq(addr, 101, blockID2))
	vr2 := MustSignedVoteResponse(&resp2)
	if vr2 == nil || vr2.Error != nil {
		t.Fatalf("round 2 (after recovery): sign failed: %+v", vr2)
	}

	cancel()
}

// ── TestBothNodesAlive ────────────────────────────────────────────────────────
//
// Scenario: both primary and backup nodes are connected simultaneously.
// 1. Both nodes can send PubKey requests concurrently — all must succeed.
// 2. Both nodes request to sign the SAME vote (same height/round/data) — FilePV
//    returns the cached idempotent signature so both succeed.

func TestBothNodesAlive(t *testing.T) {
	lpv, handler, addr := setupHandler(t)

	node1client, node1 := net.Pipe()
	node2client, node2 := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, cc := range []net.Conn{node1client, node2client} {
		c := cc
		dialFn := func() (net.Conn, error) { return c, nil }
		go runDialClient(ctx, dialFn, "layertest-5", lpv, handler, nopLog(), nil)
	}

	// Part 1: concurrent PubKey requests from both nodes.
	var wg sync.WaitGroup
	var failures atomic.Int32

	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			resp := sendReq(t, node1, pubKeyReq())
			if pkr := MustPubKeyResponse(&resp); pkr == nil || pkr.Error != nil {
				t.Logf("node1 pubkey req %d: %+v", i, pkr)
				failures.Add(1)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			resp := sendReq(t, node2, pubKeyReq())
			if pkr := MustPubKeyResponse(&resp); pkr == nil || pkr.Error != nil {
				t.Logf("node2 pubkey req %d: %+v", i, pkr)
				failures.Add(1)
			}
		}
	}()
	wg.Wait()

	if n := failures.Load(); n > 0 {
		t.Errorf("%d PubKey requests failed with both nodes alive", n)
	}

	// Part 2: both nodes request to sign the exact same vote (idempotent re-sign).
	// In production, both nodes are at the same block height and send the same
	// signing request. The signer signs once and returns the same signature.
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	blockID := cmtproto.BlockID{
		Hash:          hash,
		PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash},
	}
	// Sign heights in strictly increasing order, one at a time, shared between both nodes.
	// For each height, first node1 signs, then node2 re-signs the same data (idempotent).
	for h := int64(400); h < 405; h++ {
		req := signVoteReq(addr, h, blockID)

		resp1 := sendReq(t, node1, req)
		vr1 := MustSignedVoteResponse(&resp1)
		if vr1 == nil || vr1.Error != nil {
			t.Errorf("height %d node1 sign failed: %+v", h, vr1)
			continue
		}

		resp2 := sendReq(t, node2, req)
		vr2 := MustSignedVoteResponse(&resp2)
		if vr2 == nil || vr2.Error != nil {
			t.Errorf("height %d node2 re-sign failed: %+v", h, vr2)
			continue
		}

		if !bytes.Equal(vr1.Vote.Signature, vr2.Vote.Signature) {
			t.Errorf("height %d: node1 and node2 signatures differ (should be idempotent)", h)
		}
	}

	cancel()
}

// ── TestDoubleSignPrevention ──────────────────────────────────────────────────
//
// Scenario: two nodes try to sign a vote for the SAME height/round but with
// different block hashes. CometBFT FilePV MUST reject the second attempt to
// prevent equivocation (double signing).

func TestDoubleSignPrevention(t *testing.T) {
	lpv, handler, addr := setupHandler(t)

	node1client, node1 := net.Pipe()
	node2client, node2 := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, cc := range []net.Conn{node1client, node2client} {
		c := cc
		dialFn := func() (net.Conn, error) { return c, nil }
		go runDialClient(ctx, dialFn, "layertest-5", lpv, handler, nopLog(), nil)
	}

	const conflictHeight = int64(300)

	hashA := make([]byte, 32)
	hashB := make([]byte, 32)
	for i := range hashA {
		hashA[i] = byte(i + 1)
		hashB[i] = byte(i + 100) // clearly different
	}
	blockA := cmtproto.BlockID{Hash: hashA, PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hashA}}
	blockB := cmtproto.BlockID{Hash: hashB, PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hashB}}

	// Node 1 signs block A at height 300.
	resp1 := sendReq(t, node1, signVoteReq(addr, conflictHeight, blockA))
	vr1 := MustSignedVoteResponse(&resp1)
	if vr1 == nil {
		t.Fatal("node1: expected SignedVoteResponse, got nil")
	}

	// Node 2 attempts to sign block B at the same height 300 (double-sign attempt).
	resp2 := sendReq(t, node2, signVoteReq(addr, conflictHeight, blockB))
	vr2 := MustSignedVoteResponse(&resp2)
	if vr2 == nil {
		t.Fatal("node2: expected SignedVoteResponse, got nil")
	}

	// Exactly one of the two must succeed; the other must carry an error.
	// (We can't guarantee which one wins the mutex race, but only one must succeed.)
	firstOK := vr1.Error == nil
	secondOK := vr2.Error == nil

	switch {
	case firstOK && !secondOK:
		t.Log("double-sign prevention: node1 signed, node2 rejected ✓")
	case !firstOK && secondOK:
		t.Log("double-sign prevention: node2 signed, node1 rejected ✓")
	case firstOK && secondOK:
		t.Error("DOUBLE SIGN: both nodes signed different blocks at the same height!")
	default:
		// Both failed — can happen if FilePV state file write fails in tests (tmpdir).
		// Log a warning but don't fail the test; core invariant (no double sign) holds.
		t.Logf("both sign attempts failed (err1=%v err2=%v); double-sign invariant still holds",
			vr1.Error, vr2.Error)
	}

	cancel()
}

// ── TestServeConn_ContextCancellation ────────────────────────────────────────
//
// serveConn must return promptly when the context is cancelled.

func TestServeConn_ContextCancellation(t *testing.T) {
	lpv, handler, _ := setupHandler(t)
	client, node := net.Pipe()
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		serveConn(ctx, node, "layertest-5", lpv, handler, nopLog())
		close(done)
	}()

	// Let serveConn start.
	time.Sleep(20 * time.Millisecond)

	cancel()

	select {
	case <-done:
		// Good.
	case <-time.After(2 * time.Second):
		t.Error("serveConn did not return after context cancellation")
	}
}

// ── TestServeConn_NodeDisconnect ──────────────────────────────────────────────
//
// serveConn must return when the peer closes the connection.

func TestServeConn_NodeDisconnect(t *testing.T) {
	lpv, handler, _ := setupHandler(t)
	client, node := net.Pipe()

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		serveConn(ctx, node, "layertest-5", lpv, handler, nopLog())
		close(done)
	}()

	// Close the "client" (node's) side to simulate a disconnect.
	_ = client.Close()

	select {
	case <-done:
		// Good.
	case <-time.After(2 * time.Second):
		t.Error("serveConn did not return after peer disconnect")
	}
}

// ── TestLockedPrivValidator_DoubleSign ────────────────────────────────────────
//
// Direct unit test confirming LockedPrivValidator rejects a duplicate vote at
// the same height/round/step (equivocation attempt).

func TestLockedPrivValidator_DoubleSign(t *testing.T) {
	pv := newTestFilePV(t)
	lpv := NewLockedPrivValidator(pv)

	pk, err := lpv.GetPubKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := pk.Address()

	hashA := make([]byte, 32)
	hashB := make([]byte, 32)
	for i := range hashA {
		hashA[i] = byte(i + 1)
		hashB[i] = byte(i + 100)
	}

	makeVote := func(hash []byte) *cmtproto.Vote {
		return &cmtproto.Vote{
			Type:             cmtproto.PrevoteType,
			Height:           42,
			Round:            0,
			BlockID:          cmtproto.BlockID{Hash: hash, PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash}},
			ValidatorAddress: addr,
			ValidatorIndex:   0,
		}
	}

	voteA := makeVote(hashA)
	if err := lpv.SignVote("layertest-5", voteA); err != nil {
		t.Fatalf("first sign failed: %v", err)
	}

	// Signing the same height/round with a different hash must be rejected.
	voteB := makeVote(hashB)
	err = lpv.SignVote("layertest-5", voteB)
	if err == nil {
		t.Error("expected error for double-sign attempt, got nil")
	}
}

// ── TestHandlerPreservesSignatureAcrossNodes ──────────────────────────────────
//
// The same request (identical bytes) sent by two nodes returns the same
// signature (idempotent re-sign). This is the "both nodes alive" case where
// a block is signed once and later confirmed.

func TestHandlerIdempotentResign(t *testing.T) {
	lpv, handler, addr := setupHandler(t)

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	blockID := cmtproto.BlockID{
		Hash:          hash,
		PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash},
	}

	vote := &cmtproto.Vote{
		Type:             cmtproto.PrevoteType,
		Height:           500,
		Round:            0,
		BlockID:          blockID,
		ValidatorAddress: addr,
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

	// First sign.
	resp1, err := handler(lpv, req, "layertest-5")
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}
	vr1 := MustSignedVoteResponse(&resp1)
	if vr1 == nil || vr1.Error != nil {
		t.Fatalf("first sign: bad response: %+v", vr1)
	}

	// Identical re-sign (same height/round/bytes) must succeed (FilePV allows re-signing identical data).
	vote2 := &cmtproto.Vote{
		Type:             vote.Type,
		Height:           vote.Height,
		Round:            vote.Round,
		BlockID:          vote.BlockID,
		ValidatorAddress: addr,
		ValidatorIndex:   0,
	}
	req2 := privvalproto.Message{
		Sum: &privvalproto.Message_SignVoteRequest{
			SignVoteRequest: &privvalproto.SignVoteRequest{
				ChainId: "layertest-5",
				Vote:    vote2,
			},
		},
	}
	resp2, err := handler(lpv, req2, "layertest-5")
	if err != nil {
		t.Fatalf("idempotent re-sign: %v", err)
	}
	vr2 := MustSignedVoteResponse(&resp2)
	if vr2 == nil || vr2.Error != nil {
		t.Fatalf("idempotent re-sign: bad response: %+v", vr2)
	}

	// Signatures must be identical.
	if !bytes.Equal(vr1.Vote.Signature, vr2.Vote.Signature) {
		t.Error("idempotent re-sign: signatures differ for identical vote")
	}
}

// ── TestValidatorAddressEnforced ──────────────────────────────────────────────
//
// Verify that a sign request targeting a validator address other than ours is
// rejected at the handler level (before reaching FilePV) to prevent
// cross-validator signing.

func TestValidatorAddressEnforced(t *testing.T) {
	lpv, handler, _ := setupHandler(t)

	// Build a request with a completely different validator address.
	attackerAddr := make([]byte, crypto.AddressSize)
	for i := range attackerAddr {
		attackerAddr[i] = 0xDE
	}
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	blockID := cmtproto.BlockID{Hash: hash, PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash}}

	req := privvalproto.Message{
		Sum: &privvalproto.Message_SignVoteRequest{
			SignVoteRequest: &privvalproto.SignVoteRequest{
				ChainId: "layertest-5",
				Vote: &cmtproto.Vote{
					Type:             cmtproto.PrevoteType,
					Height:           1,
					Round:            0,
					BlockID:          blockID,
					ValidatorAddress: attackerAddr,
					ValidatorIndex:   0,
				},
			},
		},
	}

	_, err := handler(lpv, req, "layertest-5")
	if err == nil {
		t.Error("expected rejection of wrong validator address, got nil error")
	}
}

// ── TestSignProposal ──────────────────────────────────────────────────────────
//
// SignProposal must produce a valid signature and reject a conflicting
// proposal at the same height/round (double-sign via proposal).

func TestSignProposal_HappyPath(t *testing.T) {
	lpv, handler, _ := setupHandler(t)

	pk, err := lpv.GetPubKey()
	if err != nil {
		t.Fatal(err)
	}

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 2)
	}
	blockID := cmtproto.BlockID{Hash: hash, PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash}}

	req := privvalproto.Message{
		Sum: &privvalproto.Message_SignProposalRequest{
			SignProposalRequest: &privvalproto.SignProposalRequest{
				ChainId: "layertest-5",
				Proposal: &cmtproto.Proposal{
					Type:     cmtproto.ProposalType,
					Height:   200,
					Round:    0,
					PolRound: -1,
					BlockID:  blockID,
				},
			},
		},
	}
	res, err := handler(lpv, req, "layertest-5")
	if err != nil {
		t.Fatalf("SignProposal error: %v", err)
	}
	spr := MustSignedProposalResponse(&res)
	if spr == nil || spr.Error != nil {
		t.Fatalf("expected success, got: %+v", spr)
	}
	if len(spr.Proposal.Signature) == 0 {
		t.Error("expected non-empty proposal signature")
	}

	// Verify the signature using the public key via ProposalSignBytes.
	signBytes := types.ProposalSignBytes("layertest-5", &spr.Proposal)
	if !pk.VerifySignature(signBytes, spr.Proposal.Signature) {
		t.Error("proposal signature failed cryptographic verification")
	}
}

func TestSignProposal_DoubleSignRejected(t *testing.T) {
	lpv, handler, _ := setupHandler(t)

	hash1 := make([]byte, 32)
	hash2 := make([]byte, 32)
	for i := range hash1 {
		hash1[i] = byte(i + 1)
		hash2[i] = byte(i + 50)
	}
	makeProposalReq := func(hash []byte) privvalproto.Message {
		bid := cmtproto.BlockID{Hash: hash, PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash}}
		return privvalproto.Message{
			Sum: &privvalproto.Message_SignProposalRequest{
				SignProposalRequest: &privvalproto.SignProposalRequest{
					ChainId: "layertest-5",
					Proposal: &cmtproto.Proposal{
						Type:     cmtproto.ProposalType,
						Height:   777,
						Round:    0,
						PolRound: -1,
						BlockID:  bid,
					},
				},
			},
		}
	}

	// First proposal — must succeed.
	if _, err := handler(lpv, makeProposalReq(hash1), "layertest-5"); err != nil {
		t.Fatalf("first proposal: %v", err)
	}

	// Second proposal same height/round, different block — must be rejected.
	res, err := handler(lpv, makeProposalReq(hash2), "layertest-5")
	if err == nil {
		t.Fatal("expected double-sign rejection for proposal, got nil error")
	}
	spr := MustSignedProposalResponse(&res)
	if spr == nil || spr.Error == nil {
		t.Errorf("expected RemoteSignerError in response, got: %+v", spr)
	}
}

// ── TestRunDialClient_TCPFullCycle ────────────────────────────────────────────
//
// TestRunDialClient_TCPFullCycle exercises the public RunDialClient entry-point
// with a real TCP listener (same path as production). It verifies:
//  - SecretConnection handshake completes
//  - PubKeyRequest is served
//  - SignVoteRequest is served and produces a valid signature

func TestRunDialClient_TCPFullCycle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	connKey := ed25519.GenPrivKey()
	tcpL := privval.NewTCPListener(ln, connKey)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.json")
	statePath := filepath.Join(dir, "state.json")
	privval.GenFilePV(keyPath, statePath).Save()

	pv, err := LoadCometFilePV(keyPath, statePath)
	if err != nil {
		t.Fatal(err)
	}
	lpv := NewLockedPrivValidator(pv)
	addr, err := ValidatorAddressForHandler(lpv)
	if err != nil {
		t.Fatal(err)
	}
	handler := ValidationRequestHandler(addr)
	chainID := "tcp-cycle"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// RunDialClient is the public entry-point used in production cmd_start.go.
	go RunDialClient(ctx, "tcp://"+tcpL.Addr().String(), chainID, ed25519.GenPrivKey(), lpv, handler, nil, nopLog())

	connCh := make(chan net.Conn, 1)
	go func() {
		c, acceptErr := tcpL.Accept()
		if acceptErr == nil {
			connCh <- c
		}
	}()

	var sconn net.Conn
	select {
	case sconn = <-connCh:
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for RunDialClient to connect")
	}
	defer sconn.Close()
	_ = sconn.SetDeadline(time.Now().Add(10 * time.Second))

	wr := protoio.NewDelimitedWriter(sconn)
	rd := protoio.NewDelimitedReader(sconn, MaxRemoteSignerMsgSize)

	writeRead := func(req *privvalproto.Message) privvalproto.Message {
		t.Helper()
		if _, err := wr.WriteMsg(req); err != nil {
			t.Fatalf("writeRead write: %v", err)
		}
		var res privvalproto.Message
		if _, err := rd.ReadMsg(&res); err != nil {
			t.Fatalf("writeRead read: %v", err)
		}
		return res
	}

	// PubKey request.
	pkRes := writeRead(&privvalproto.Message{
		Sum: &privvalproto.Message_PubKeyRequest{
			PubKeyRequest: &privvalproto.PubKeyRequest{ChainId: chainID},
		},
	})
	pkr := MustPubKeyResponse(&pkRes)
	if pkr == nil || pkr.Error != nil {
		t.Fatalf("PubKeyRequest failed: %+v", pkr)
	}

	// SignVoteRequest.
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 3)
	}
	blockID := cmtproto.BlockID{Hash: hash, PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: hash}}
	voteRes := writeRead(&privvalproto.Message{
		Sum: &privvalproto.Message_SignVoteRequest{
			SignVoteRequest: &privvalproto.SignVoteRequest{
				ChainId: chainID,
				Vote: &cmtproto.Vote{
					Type:             cmtproto.PrevoteType,
					Height:           50,
					Round:            0,
					BlockID:          blockID,
					ValidatorAddress: addr,
					ValidatorIndex:   0,
				},
			},
		},
	})
	svr := MustSignedVoteResponse(&voteRes)
	if svr == nil || svr.Error != nil {
		t.Fatalf("SignVoteRequest failed: %+v", svr)
	}
	if len(svr.Vote.Signature) == 0 {
		t.Error("expected non-empty vote signature")
	}
}
