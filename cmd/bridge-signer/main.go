//go:build !windows

// bridge-signer is the gRPC remote signing daemon. The build is gated on
// Unix: the signer relies on POSIX file mode bits for key file secrecy
// (NTFS ACLs are not reflected by os.FileMode) and on SIGTERM for
// graceful service stop. Refusing to build on Windows avoids shipping
// a binary with silently weakened guarantees.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	bridgetls "github.com/tellor-io/bridge-remote-signer/api/tls"
	"github.com/tellor-io/bridge-remote-signer/config"
	"github.com/tellor-io/bridge-remote-signer/health"
	"github.com/tellor-io/bridge-remote-signer/logging"
	"github.com/tellor-io/bridge-remote-signer/server"
	"github.com/tellor-io/bridge-remote-signer/signer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "config.yaml", "path to config file")
		// Subcommands
		keygen       = flag.Bool("keygen", false, "generate a new secp256k1 key file and exit")
		importKey    = flag.Bool("import", false, "import an existing secp256k1 private key (hex from stdin) and exit")
		show         = flag.Bool("show", false, "print the public key and addresses for an existing key file and exit")
		export       = flag.Bool("export", false, "print the raw hex private key to stdout and exit")
		keyOut       = flag.String("out", "", "output path for key file (used with --keygen or --import)")
		keyIn        = flag.String("key", "", "path to an existing key file (used with --show or --export)")
		passwordFile = flag.String("password-file", "", "path to password file (used with --keygen, --import, --show, or --export; prompts if unset)")
	)
	flag.Parse()

	switch {
	case *keygen:
		return runKeygen(*keyOut, *passwordFile)
	case *importKey:
		return runImport(*keyOut, *passwordFile)
	case *show:
		return runShow(*keyIn, *passwordFile)
	case *export:
		return runExport(*keyIn, *passwordFile)
	}

	// Load and validate config.
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger first
	logger, err := logging.New(cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Initialize the signing backend.
	s, err := signer.NewSigner(context.Background(), string(cfg.Signer.Backend), cfg.Signer.ToMap())
	if err != nil {
		return fmt.Errorf("failed to initialize signer: %w", err)
	}

	pubKey, err := s.GetPublicKey(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}
	ecdsaPubKey, err := crypto.DecompressPubkey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to decompress public key: %w", err)
	}
	ethAddr := crypto.PubkeyToAddress(*ecdsaPubKey).Hex()

	logger.Info("signer initialized",
		"backend", cfg.Signer.Backend,
		"eth_address", ethAddr,
	)

	// Build mTLS server credentials.
	creds, err := bridgetls.NewServerCredentials(
		cfg.TLS.CACert,
		cfg.TLS.ServerCert,
		cfg.TLS.ServerKey,
	)
	if err != nil {
		return fmt.Errorf("failed to build TLS credentials: %w", err)
	}

	// Build and register the gRPC server.
	srv := server.New(s, logger, server.Config{
		ListenAddr:     cfg.Server.ListenAddr,
		RequestTimeout: cfg.Server.RequestTimeout,
		MaxRecvMsgSize: cfg.Server.MaxRecvMsgSize,
		Credentials:    creds,
	})

	// Log startup confirms config loaded correctly before we start serving.
	logger.AuditStartup(string(cfg.Signer.Backend), cfg.Server.ListenAddr)

	// Listen for SIGINT and SIGTERM for a graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start the gRPC server in a goroutine so we can wait for signals.
	errCh := make(chan error, 2)

	// Start health check server on a separate port.
	healthChecker := health.New(s, logger, cfg.Server.HealthAddr)
	go func() {
		if err := healthChecker.Start(); err != nil {
			logger.Error("health check server error", "error", err)
			errCh <- fmt.Errorf("health check server: %w", err)
		}
	}()

	go func() {
		errCh <- srv.Start()
	}()

	// Block until we receive a signal or the server exits with an error.
	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig.String())
		srv.Stop() // GracefulStop
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		healthChecker.Stop(shutdownCtx)
		return nil

	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server exited unexpectedly: %w", err)
		}
		return nil
	}
}
