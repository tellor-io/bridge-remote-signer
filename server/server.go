package server

import (
	"context"
	"fmt"
	"net"
	"time"

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
}

// Config holds the server configuration.
type Config struct {
	ListenAddr     string
	RequestTimeout time.Duration
	MaxRecvMsgSize int
	Credentials    credentials.TransportCredentials
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
