package server

import (
	"context"
	"fmt"
	"net"
	"time"

	cosmossecp "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types/bech32"
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

	signer         signer.Signer
	logger         *logging.Logger
	requestTimeout time.Duration
	listenAddr     string
	grpcServer     *grpc.Server
	chainID        string
}

// Config holds the server configuration.
type Config struct {
	ListenAddr     string
	RequestTimeout time.Duration
	MaxRecvMsgSize int
	Credentials    credentials.TransportCredentials
	ChainID        string
}

// New creates a Server with the given signer backend and config.
func New(s signer.Signer, logger *logging.Logger, cfg Config) *Server {
	// Unary interceptor — applied to every RPC call.
	// Handles: request timeout enforcement, panic recovery, peer logging.
	interceptor := newUnaryInterceptor(logger, cfg.RequestTimeout)

	grpcServer := grpc.NewServer(
		grpc.Creds(cfg.Credentials),
		grpc.UnaryInterceptor(interceptor),
		grpc.MaxRecvMsgSize(cfg.MaxRecvMsgSize),
	)

	srv := &Server{
		signer:         s,
		logger:         logger,
		requestTimeout: cfg.RequestTimeout,
		listenAddr:     cfg.ListenAddr,
		grpcServer:     grpcServer,
		chainID:        cfg.ChainID,
	}

	signerv1.RegisterBridgeSignerServer(grpcServer, srv)
	reflection.Register(grpcServer)

	return srv
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

// Sign implements BridgeSignerServer.
// Validates the request, calls the signing backend, and returns the signature.
func (s *Server) Sign(ctx context.Context, req *signerv1.SignRequest) (*signerv1.SignResponse, error) {
	start := time.Now()

	// Validate message length which must be exactly 32 bytes.
	if len(req.Msg) != 32 {
		err := status.Errorf(codes.InvalidArgument,
			"msg must be exactly 32 bytes, got %d", len(req.Msg))
		s.logger.AuditSign(ctx, req.RequestId, req.Msg, err, time.Since(start))
		return nil, err
	}

	sig, err := s.signer.Sign(ctx, req.Msg)
	s.logger.AuditSign(ctx, req.RequestId, req.Msg, err, time.Since(start))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "signing failed: %v", err)
	}

	return &signerv1.SignResponse{Signature: sig}, nil
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

// SignRaw signs the given 32-byte hash directly without any additional hashing.
// Returns a 64-byte secp256k1 signature (r || s) compatible with Cosmos SDK tx signing.
// Used by the reporter to sign transactions without a local keyring.
func (s *Server) SignRaw(ctx context.Context, req *signerv1.SignRawRequest) (*signerv1.SignRawResponse, error) {
	start := time.Now()

	if len(req.Msg) != 32 {
		err := status.Errorf(codes.InvalidArgument,
			"msg must be exactly 32 bytes, got %d", len(req.Msg))
		s.logger.AuditSign(ctx, req.RequestId, req.Msg, err, time.Since(start))
		return nil, err
	}

	sig, sigErr := s.signer.SignRaw(ctx, req.Msg)
	s.logger.AuditSign(ctx, req.RequestId, req.Msg, sigErr, time.Since(start))
	if sigErr != nil {
		return nil, status.Errorf(codes.Internal, "signing failed: %v", sigErr)
	}

	return &signerv1.SignRawResponse{Signature: sig}, nil
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

// GetChainID returns the cosmos chain ID the signer is configured for, so
// callers (e.g. the monitor) can discover it at startup without a local env var.
func (s *Server) GetChainID(_ context.Context, _ *signerv1.GetChainIDRequest) (*signerv1.GetChainIDResponse, error) {
	if s.chainID == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "chain ID is not configured on the signer")
	}
	return &signerv1.GetChainIDResponse{ChainId: s.chainID}, nil
}

// enforces a per-request timeout
// recovers from panics in the handler (prevents a bad request from crashing the sidecar)
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
