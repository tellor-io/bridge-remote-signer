package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	cosmossecp "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	costx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	signerv1 "github.com/tellor-io/bridge-remote-signer/api/gen/signer/v1"
	"github.com/tellor-io/bridge-remote-signer/logging"
	"github.com/tellor-io/bridge-remote-signer/signer"
)

// Server is the gRPC server that wraps the signing backend and exposes
// the BridgeSigner RPC service to the validator node.
type Server struct {
	signerv1.UnimplementedBridgeSignerServer

	signer          signer.Signer
	logger          *logging.Logger
	requestTimeout  time.Duration
	listenAddr      string
	grpcServer      *grpc.Server
	allowedMsgTypes map[string]struct{} // set derived from Config.AllowedMsgTypes
	chainID         string

	// selfEVMAddr is the signer's own 20-byte EVM address, derived from its
	// secp256k1 public key at construction. Used for the self-membership gate
	// in SignBridgeCheckpoint (the signer refuses to sign a checkpoint for a
	// validator set it is not a member of).
	selfEVMAddr common.Address

	// checkpointGuard enforces a monotonic replay guard on the bridge
	// checkpoint validator_timestamp.
	checkpointGuard *checkpointReplayGuard

	// enabledRPCs[method]==false disables that RPC (returns Unimplemented).
	// A missing key means enabled (default-on).
	enabledRPCs map[string]bool
}

// Config holds the server configuration.
type Config struct {
	ListenAddr     string
	RequestTimeout time.Duration
	MaxRecvMsgSize int
	Credentials    credentials.TransportCredentials
	// AllowedMsgTypes is the set of Cosmos message type_urls permitted by SignTx.
	// If empty, SignTx rejects all requests (safe default).
	AllowedMsgTypes []string
	// ChainID is the cosmos chain ID, returned by GetChainID.
	ChainID string

	// CheckpointGuardStatePath is the path to the small high-water-mark file
	// used by the SignBridgeCheckpoint monotonic replay guard. Empty => the
	// guard is in-memory only (no cross-restart protection).
	CheckpointGuardStatePath string

	// EnabledRPCs[method]==false disables that RPC (returns Unimplemented).
	// A missing key means enabled (default-on), so all RPCs are enabled unless
	// explicitly turned off.
	EnabledRPCs map[string]bool

	// EnableReflection registers the gRPC reflection service. Off by default;
	// reflection lets any connected client enumerate the signing RPCs, so it
	// should stay off in production.
	EnableReflection bool
}

// New creates a Server with the given signer backend and config.
// It derives the signer's own EVM address (for the SignBridgeCheckpoint
// self-membership gate) and loads the checkpoint replay guard, so it may fail.
func New(s signer.Signer, logger *logging.Logger, cfg Config) (*Server, error) {
	// Derive the signer's own 20-byte EVM address from its compressed pubkey.
	pubKey, err := s.GetPublicKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("get public key for self EVM address: %w", err)
	}
	ecdsaPub, err := crypto.DecompressPubkey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("decompress public key for self EVM address: %w", err)
	}
	selfEVMAddr := crypto.PubkeyToAddress(*ecdsaPub)

	guard, err := newCheckpointReplayGuard(cfg.CheckpointGuardStatePath)
	if err != nil {
		return nil, fmt.Errorf("init checkpoint replay guard: %w", err)
	}

	enabled := make(map[string]bool, len(cfg.EnabledRPCs))
	for m, v := range cfg.EnabledRPCs {
		enabled[m] = v
	}

	// Unary interceptors — applied to every RPC call, in order:
	//  1. observability (timeout, panic recovery, peer logging)
	//  2. enabled-RPC gate (disabled methods => Unimplemented)
	//
	// Authorization is by OPERATION, not by client certificate: each handler is
	// either a fixed, recompute-and-verify operation (SignBridgeCheckpoint,
	// SignOracleAttestation), a config-scoped operation (SignTx allowlist), or a
	// hard-disabled blind primitive (Sign, SignRaw). mTLS is still required for
	// transport, but the CN is not consulted for authorization.
	interceptor := chainUnaryInterceptors(
		newUnaryInterceptor(logger, cfg.RequestTimeout),
		newEnabledRPCInterceptor(enabled),
	)

	grpcServer := grpc.NewServer(
		grpc.Creds(cfg.Credentials),
		grpc.UnaryInterceptor(interceptor),
		grpc.MaxRecvMsgSize(cfg.MaxRecvMsgSize),
	)

	allowed := make(map[string]struct{}, len(cfg.AllowedMsgTypes))
	for _, t := range cfg.AllowedMsgTypes {
		allowed[t] = struct{}{}
	}

	srv := &Server{
		signer:          s,
		logger:          logger,
		requestTimeout:  cfg.RequestTimeout,
		listenAddr:      cfg.ListenAddr,
		grpcServer:      grpcServer,
		allowedMsgTypes: allowed,
		chainID:         cfg.ChainID,
		selfEVMAddr:     selfEVMAddr,
		checkpointGuard: guard,
		enabledRPCs:     enabled,
	}

	signerv1.RegisterBridgeSignerServer(grpcServer, srv)
	if cfg.EnableReflection {
		reflection.Register(grpcServer)
	}

	return srv, nil
}

// Start begins listening on cfg.ListenAddr and blocks until the server stops.
func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %q: %w", s.listenAddr, err)
	}

	s.logger.Info("gRPC server listening", "addr", s.listenAddr)

	if err := s.grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("gRPC server exited with error: %w", err)
	}

	return nil
}

// ServeOn starts the gRPC server on the provided listener and blocks until
// the server stops. Useful for testing with a pre-bound listener.
func (s *Server) ServeOn(lis net.Listener) error {
	if err := s.grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("gRPC server exited with error: %w", err)
	}
	return nil
}

// Stop triggers a graceful shutdown and waits for inflight RPCs to complete
// before closing the listener. Called on OS signal in main.go.
func (s *Server) Stop() {
	s.logger.AuditShutdown()
	s.grpcServer.GracefulStop()
}

// blindSigningDisabledMsg is returned by the hard-disabled blind primitives.
const blindSigningDisabledMsg = "blind signing is disabled; use SignTx / SignBridgeCheckpoint / SignOracleAttestation"

// Sign implements BridgeSignerServer but is HARD-DISABLED: the blind 65-byte
// primitive can never sign under any configuration, so it always returns
// Unimplemented. Sign(x) yields the same r||s as SignRaw(sha256(x)) once the v
// byte is stripped, which made it a checkpoint/attestation-forgery oracle; with
// Sign unreachable that vector is closed. Use the recompute-and-verify
// operations (SignBridgeCheckpoint / SignOracleAttestation) or the scoped SignTx.
func (s *Server) Sign(_ context.Context, _ *signerv1.SignRequest) (*signerv1.SignResponse, error) {
	return nil, status.Error(codes.Unimplemented, blindSigningDisabledMsg)
}

// GetPublicKey returns the compressed secp256k1 public key so the validator node
func (s *Server) GetPublicKey(ctx context.Context, _ *signerv1.GetPublicKeyRequest) (*signerv1.GetPublicKeyResponse, error) {
	pubKey, err := s.signer.GetPublicKey(ctx)
	s.logger.AuditGetPublicKey(ctx, err)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get public key: %v", err)
	}

	if len(pubKey) != 33 {
		return nil, status.Errorf(codes.Internal, "invalid public key length %d, expected 33", len(pubKey))
	}

	return &signerv1.GetPublicKeyResponse{PublicKey: pubKey}, nil
}

// SignRaw implements BridgeSignerServer but is HARD-DISABLED: the blind 64-byte
// primitive can never sign under any configuration, so it always returns
// Unimplemented. SignRaw over an arbitrary 32-byte hash is a blind-signing fund
// vector (it can forge a valset checkpoint or oracle attestation), so the
// externally-reachable RPC is removed. The internal s.signer.SignRaw backend
// helper remains and is used by SignTx / SignBridgeCheckpoint /
// SignOracleAttestation, which only sign values they have recomputed and
// verified themselves.
func (s *Server) SignRaw(_ context.Context, _ *signerv1.SignRawRequest) (*signerv1.SignRawResponse, error) {
	return nil, status.Error(codes.Unimplemented, blindSigningDisabledMsg)
}

// GetAddress derives the bech32 address from the signer's secp256k1 public key
// using the given prefix (e.g. "tellor"). Allows the reporter to discover its
// own address at startup without hard-coding it in config.
func (s *Server) GetAddress(ctx context.Context, req *signerv1.GetAddressRequest) (*signerv1.GetAddressResponse, error) {
	if req.Prefix == "" {
		return nil, status.Errorf(codes.InvalidArgument, "prefix must not be empty")
	}

	pubKeyBytes, err := s.signer.GetPublicKey(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get public key: %v", err)
	}

	if len(pubKeyBytes) != 33 {
		return nil, status.Errorf(codes.Internal, "invalid public key length %d, expected 33", len(pubKeyBytes))
	}

	// Use the Cosmos SDK secp256k1 PubKey type to derive the address via
	// sha256 + ripemd160 of the compressed public key — the standard Cosmos derivation.
	pubKey := &cosmossecp.PubKey{Key: pubKeyBytes}
	addrBytes := pubKey.Address().Bytes()

	bech32Addr, err := bech32.ConvertAndEncode(req.Prefix, addrBytes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "bech32 encode failed: %v", err)
	}

	return &signerv1.GetAddressResponse{Address: bech32Addr}, nil
}

// GetChainID implements BridgeSignerServer. Returns the configured cosmos chain ID
// so callers (e.g. the monitor) can discover it without a local env var.
func (s *Server) GetChainID(_ context.Context, _ *signerv1.GetChainIDRequest) (*signerv1.GetChainIDResponse, error) {
	if s.chainID == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "chain ID is not configured on the signer")
	}
	return &signerv1.GetChainIDResponse{ChainId: s.chainID}, nil
}

// SignTx implements BridgeSignerServer.
// Decodes the SignDoc, validates every message type_url against the allowlist,
// then sha256-hashes the raw bytes and signs with SignRaw.
func (s *Server) SignTx(ctx context.Context, req *signerv1.SignTxRequest) (*signerv1.SignTxResponse, error) {
	if len(req.SignDoc) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "sign_doc must not be empty")
	}

	// Decode the SignDoc to extract body_bytes.
	var signDoc costx.SignDoc
	if err := signDoc.Unmarshal(req.SignDoc); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode sign_doc: %v", err)
	}

	// Decode the TxBody to iterate over message type_urls.
	var body costx.TxBody
	if err := body.Unmarshal(signDoc.BodyBytes); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode tx body: %v", err)
	}

	// A SignDoc with zero messages would skip the allowlist loop entirely and
	// fall through to signing — fail closed instead. (Such a tx is also invalid
	// on-chain, where ValidateBasic requires at least one message.)
	if len(body.Messages) == 0 {
		return nil, status.Errorf(codes.PermissionDenied, "sign_doc carries no messages")
	}

	// Validate every message type against the allowlist.
	for _, msg := range body.Messages {
		typeURL := msg.TypeUrl
		if _, ok := s.allowedMsgTypes[typeURL]; !ok {
			s.logger.Error("SignTx rejected: message type not on allowlist",
				"type_url", typeURL,
				"request_id", req.RequestId,
			)
			return nil, status.Errorf(codes.PermissionDenied,
				"message type %q is not allowed", typeURL)
		}
	}

	// Hash and sign.
	hash := sha256.Sum256(req.SignDoc)
	sig, err := s.signer.SignRaw(ctx, hash[:])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "signing failed: %v", err)
	}

	s.logger.AuditSign(ctx, req.RequestId, hash[:], nil, 0)
	return &signerv1.SignTxResponse{Signature: sig}, nil
}

// SignBridgeCheckpoint implements BridgeSignerServer.
//
// Unlike a blind hash-signer, this RECOMPUTES the valset checkpoint from the
// structured inputs using the byte-exact node encoder, validates it against the
// caller-supplied expected_checkpoint, and only then signs sha256(checkpoint)
// via the 64-byte SignRaw backend. It FAILS CLOSED (signs nothing) on any
// mismatch. Returned signature is 64-byte r||s — the chain consumer
// (TryRecoverAddressWithBothIDs) requires len(sig)==64 and brute-forces the
// recovery id itself.
func (s *Server) SignBridgeCheckpoint(ctx context.Context, req *signerv1.SignBridgeCheckpointRequest) (*signerv1.SignBridgeCheckpointResponse, error) {
	start := time.Now()

	// (1) Format / range gates. FAIL CLOSED on any malformed input.
	if len(req.DomainSeparator) != 32 {
		return nil, status.Errorf(codes.InvalidArgument, "domain_separator must be 32 bytes, got %d", len(req.DomainSeparator))
	}
	if len(req.ValidatorSetHash) != 32 {
		return nil, status.Errorf(codes.InvalidArgument, "validator_set_hash must be 32 bytes, got %d", len(req.ValidatorSetHash))
	}
	if len(req.ExpectedCheckpoint) != 32 {
		return nil, status.Errorf(codes.InvalidArgument, "expected_checkpoint must be 32 bytes, got %d", len(req.ExpectedCheckpoint))
	}
	if len(req.ValidatorSet) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "validator_set must not be empty")
	}
	if req.ChainId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "chain_id must not be empty")
	}

	vs := make([]bridgeValidator, 0, len(req.ValidatorSet))
	for i, v := range req.ValidatorSet {
		if len(v.EthereumAddress) != 20 {
			return nil, status.Errorf(codes.InvalidArgument,
				"validator_set[%d].ethereum_address must be 20 bytes, got %d", i, len(v.EthereumAddress))
		}
		if v.Power == 0 {
			return nil, status.Errorf(codes.InvalidArgument, "validator_set[%d].power must be > 0", i)
		}
		addr := make([]byte, 20)
		copy(addr, v.EthereumAddress)
		vs = append(vs, bridgeValidator{EthereumAddress: addr, Power: v.Power})
	}

	// Re-sort into node canonical order; never trust caller ordering.
	sortBridgeValidators(vs)

	// (2) Recompute valset hash from the structured set; assert equality.
	_, valsetHash, err := encodeAndHashValidatorSet(vs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode validator set: %v", err)
	}
	if !bytes.Equal(valsetHash, req.ValidatorSetHash) {
		s.logger.Error("SignBridgeCheckpoint rejected: validator_set_hash mismatch",
			"request_id", req.RequestId,
			"computed", hex.EncodeToString(valsetHash),
			"claimed", hex.EncodeToString(req.ValidatorSetHash),
		)
		return nil, status.Errorf(codes.InvalidArgument, "validator_set_hash mismatch")
	}

	// (3) Recompute powerThreshold = sum(powers)*2/3 (node integer math); assert.
	var totalPower uint64
	for _, v := range vs {
		totalPower += v.Power
	}
	wantThreshold := totalPower * 2 / 3
	if wantThreshold != req.PowerThreshold {
		return nil, status.Errorf(codes.InvalidArgument,
			"power_threshold mismatch: computed %d, claimed %d", wantThreshold, req.PowerThreshold)
	}

	// (4) Recompute the domain separator from chain_id; assert equality.
	domainSep, err := computeDomainSeparator(req.ChainId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "compute domain separator: %v", err)
	}
	if !bytes.Equal(domainSep, req.DomainSeparator) {
		return nil, status.Errorf(codes.InvalidArgument, "domain_separator mismatch for chain_id %q", req.ChainId)
	}

	// (5) Self-membership: the signer's own EVM address must be in the set.
	member := false
	for _, v := range vs {
		if common.BytesToAddress(v.EthereumAddress) == s.selfEVMAddr {
			member = true
			break
		}
	}
	if !member {
		s.logger.Error("SignBridgeCheckpoint rejected: signer not a member of validator_set",
			"request_id", req.RequestId,
			"self_evm_addr", s.selfEVMAddr.Hex(),
		)
		return nil, status.Errorf(codes.PermissionDenied, "signer is not a member of the validator set")
	}

	// (6) Recompute the checkpoint; assert byte-equal to expected_checkpoint.
	checkpoint, err := encodeValsetCheckpoint(domainSep, req.PowerThreshold, req.ValidatorTimestamp, valsetHash)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode checkpoint: %v", err)
	}
	if !bytes.Equal(checkpoint, req.ExpectedCheckpoint) {
		s.logger.Error("SignBridgeCheckpoint rejected: checkpoint mismatch",
			"request_id", req.RequestId,
			"computed", hex.EncodeToString(checkpoint),
			"expected", hex.EncodeToString(req.ExpectedCheckpoint),
		)
		return nil, status.Errorf(codes.InvalidArgument, "checkpoint mismatch")
	}

	// (7) Monotonic replay guard: reject ts <= last persisted, then persist.
	if err := s.checkpointGuard.CheckAndAdvance(req.ValidatorTimestamp); err != nil {
		s.logger.Error("SignBridgeCheckpoint rejected: replay guard",
			"request_id", req.RequestId,
			"validator_timestamp", req.ValidatorTimestamp,
			"error", err.Error(),
		)
		return nil, status.Errorf(codes.FailedPrecondition, "replay guard: %v", err)
	}

	// (8) Sign sha256(checkpoint) via the 64-byte SignRaw backend.
	digest := sha256.Sum256(checkpoint)
	sig, sigErr := s.signer.SignRaw(ctx, digest[:])
	s.logger.AuditSign(ctx, req.RequestId, digest[:], sigErr, time.Since(start))
	if sigErr != nil {
		return nil, status.Errorf(codes.Internal, "signing failed: %v", sigErr)
	}
	if len(sig) != 64 {
		return nil, status.Errorf(codes.Internal, "invalid signature length %d, expected 64", len(sig))
	}

	s.logger.Info("SignBridgeCheckpoint completed",
		"event", "sign_bridge_checkpoint",
		"request_id", req.RequestId,
		"remote_addr", peerAddr(ctx),
		"chain_id", req.ChainId,
		"block_height", req.BlockHeight,
		"checkpoint_index", req.CheckpointIndex,
		"validator_timestamp", req.ValidatorTimestamp,
		"checkpoint", hex.EncodeToString(checkpoint),
		"success", true,
	)

	return &signerv1.SignBridgeCheckpointResponse{
		Signature:  sig,
		Checkpoint: checkpoint,
	}, nil
}

// SignOracleAttestation implements BridgeSignerServer.
//
// Like SignBridgeCheckpoint, this RECOMPUTES the attestation snapshot from the
// structured inputs using the byte-exact node encoder (EncodeOracleAttestationData),
// validates it against the caller-supplied expected_snapshot, and only then signs
// sha256(snapshot) via the 64-byte SignRaw backend helper. It FAILS CLOSED (signs
// nothing) on any mismatch. Returned signature is 64-byte r||s — the chain
// consumer requires len(sig)==64 and brute-forces the recovery id itself.
func (s *Server) SignOracleAttestation(ctx context.Context, req *signerv1.SignOracleAttestationRequest) (*signerv1.SignOracleAttestationResponse, error) {
	start := time.Now()

	// (1) Format / length gates. FAIL CLOSED on any malformed input.
	// query_id and valset_checkpoint are copied into [32]byte by the encoder, so
	// they must not exceed 32 bytes (front-aligned, right zero-padded if shorter).
	if len(req.QueryId) == 0 || len(req.QueryId) > 32 {
		return nil, status.Errorf(codes.InvalidArgument, "query_id must be 1..32 bytes, got %d", len(req.QueryId))
	}
	if len(req.ValsetCheckpoint) != 32 {
		return nil, status.Errorf(codes.InvalidArgument, "valset_checkpoint must be 32 bytes, got %d", len(req.ValsetCheckpoint))
	}
	if len(req.ExpectedSnapshot) != 32 {
		return nil, status.Errorf(codes.InvalidArgument, "expected_snapshot must be 32 bytes, got %d", len(req.ExpectedSnapshot))
	}

	// (2) Recompute the snapshot from the structured inputs via the byte-exact
	// node encoder. value carries the already-hex-decoded bytes (the node decodes
	// the value string before packing); the signer packs them as dynamic `bytes`.
	snapshot, err := encodeOracleAttestation(
		req.QueryId,
		req.Value,
		req.Timestamp,
		req.AggregatePower,
		req.PreviousTimestamp,
		req.NextTimestamp,
		req.ValsetCheckpoint,
		req.AttestationTimestamp,
		req.LastConsensusTimestamp,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode oracle attestation: %v", err)
	}

	// (3) Cross-check the recomputed snapshot against the caller-supplied value.
	// FAIL CLOSED (sign nothing) on mismatch.
	if !bytes.Equal(snapshot, req.ExpectedSnapshot) {
		s.logger.Error("SignOracleAttestation rejected: snapshot mismatch",
			"request_id", req.RequestId,
			"computed", hex.EncodeToString(snapshot),
			"expected", hex.EncodeToString(req.ExpectedSnapshot),
		)
		return nil, status.Errorf(codes.InvalidArgument, "snapshot mismatch")
	}

	// (4) Sign sha256(snapshot) via the 64-byte SignRaw backend helper.
	digest := sha256.Sum256(snapshot)
	sig, sigErr := s.signer.SignRaw(ctx, digest[:])
	s.logger.AuditSign(ctx, req.RequestId, digest[:], sigErr, time.Since(start))
	if sigErr != nil {
		return nil, status.Errorf(codes.Internal, "signing failed: %v", sigErr)
	}
	if len(sig) != 64 {
		return nil, status.Errorf(codes.Internal, "invalid signature length %d, expected 64", len(sig))
	}

	s.logger.Info("SignOracleAttestation completed",
		"event", "sign_oracle_attestation",
		"request_id", req.RequestId,
		"remote_addr", peerAddr(ctx),
		"timestamp", req.Timestamp,
		"aggregate_power", req.AggregatePower,
		"snapshot", hex.EncodeToString(snapshot),
		"success", true,
	)

	return &signerv1.SignOracleAttestationResponse{
		Signature: sig,
		Snapshot:  snapshot,
	}, nil
}

// enforces a per-request timeout
// recovers from panics in the handler (prevents a bad request from crashing the sidecar)
// peerAddr returns the remote peer address from ctx, or "unknown" if absent.
// Included in the sign-completion logs so an operator can see which node's
// request was signed during active-passive failover without enabling debug.
func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return "unknown"
}

// logs the remote peer address for each connection
func newUnaryInterceptor(logger *logging.Logger, timeout time.Duration) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		// Log the peer address for connection auditing.
		if p, ok := peer.FromContext(ctx); ok {
			logger.AuditConnection(p.Addr.String())
		}

		// Enforce request timeout so a slow signing backend can't hang the validator's consensus loop.
		timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		// Recover from panics so a single bad request doesn't kill the sidecar.
		defer func() {
			if r := recover(); r != nil {
				logger.Error("panic recovered in gRPC handler",
					"method", info.FullMethod,
					"panic", r,
				)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(timeoutCtx, req)
	}
}
