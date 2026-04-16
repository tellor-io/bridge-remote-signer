package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
		keygen = flag.Bool("keygen", false, "generate a new secp256k1 key file and exit")
		keyOut = flag.String("out", "", "output path for generated key (used with --keygen)")
		pubkey = flag.Bool("pubkey", false, "print the public key and operator address for a key file and exit")
		keyIn  = flag.String("key", "", "key file path (used with --pubkey)")
	)
	flag.Parse()

	// keygen: generate a new secp256k1 key file
	if *keygen {
		if *keyOut == "" {
			return errors.New("--out is required with --keygen")
		}
		if err := signer.GenerateKeyToFile(*keyOut); err != nil {
			return fmt.Errorf("keygen failed: %w", err)
		}
		fmt.Printf("generated secp256k1 key at %s\n", *keyOut)

		return nil
	}

	if *pubkey {
		if *keyIn == "" {
			return errors.New("--key is required with --pubkey")
		}
		pubKeyHex, ethAddr, err := signer.PublicKeyFromFile(*keyIn)
		if err != nil {
			return fmt.Errorf("pubkey failed: %w", err)
		}
		fmt.Printf("compressed public key : %s\n", pubKeyHex)
		fmt.Printf("ethereum address      : %s\n", ethAddr)
		fmt.Println("verify the ethereum address matches what is registered with the bridge contract")
		return nil
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
		// Close the signer backend if it supports it (e.g. YubiHSM session cleanup).
		if closer, ok := s.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				logger.Error("failed to close signer backend", "error", err)
			}
		}
		return nil

	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server exited unexpectedly: %w", err)
		}
		return nil
	}
}
