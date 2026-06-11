package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	bridgetls "github.com/tellor-io/bridge-remote-signer/api/tls"
	"github.com/tellor-io/bridge-remote-signer/config"
	"github.com/tellor-io/bridge-remote-signer/consensus"
	"github.com/tellor-io/bridge-remote-signer/health"
	"github.com/tellor-io/bridge-remote-signer/logging"
	"github.com/tellor-io/bridge-remote-signer/server"
	"github.com/tellor-io/bridge-remote-signer/signer"
)

const (
	shutdownTimeout = 5 * time.Second
)

func startCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the bridge-signer gRPC daemon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			return runDaemon(configPath)
		},
	}
	cmd.Flags().String("config", "config.yaml", "path to config file")
	return cmd
}

func runDaemon(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Initialize logger first
	logger, err := logging.New(cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		return fmt.Errorf("initialize logger: %w", err)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	initSigCh := make(chan os.Signal, 1)
	signal.Notify(initSigCh, syscall.SIGINT, syscall.SIGTERM)

	initCtx, cancelInit := context.WithCancel(context.Background())
	defer cancelInit()

	initDone := make(chan struct{})
	go func() {
		select {
		case <-initSigCh:
			cancelInit()
		case <-initDone:
		}
	}()

	s, err := signer.NewSigner(initCtx, string(cfg.Signer.Backend), cfg.Signer.ToMap())
	close(initDone)
	signal.Stop(initSigCh)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			logger.Info("startup canceled")
			return nil
		}
		return fmt.Errorf("initialize signer: %w", err)
	}
	defer func() {
		if closer, ok := s.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()

	pubKey, err := s.GetPublicKey(context.Background())
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}
	ecdsaPubKey, err := crypto.DecompressPubkey(pubKey)
	if err != nil {
		return fmt.Errorf("decompress public key: %w", err)
	}
	ethAddr := crypto.PubkeyToAddress(*ecdsaPubKey).Hex()

	logger.Info("signer initialized",
		"backend", cfg.Signer.Backend,
		"eth_address", ethAddr,
	)

	ctx, ctxCancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer ctxCancel()

	var consensusWg sync.WaitGroup
	if cfg.Consensus.Enabled() {
		cometLogger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))

		connKey, err := consensus.GenOrLoadConnKey(cfg.Consensus.ConnKeyFile)
		if err != nil {
			return fmt.Errorf("load consensus connection key: %w", err)
		}
		filePV, err := consensus.LoadCometFilePV(cfg.Consensus.KeyFile, cfg.Consensus.StateFile)
		if err != nil {
			return fmt.Errorf("consensus: load validator key: %w", err)
		}
		locked := consensus.NewLockedPrivValidator(filePV)
		valAddr, err := consensus.ValidatorAddressForHandler(locked)
		if err != nil {
			return fmt.Errorf("consensus: get validator address: %w", err)
		}
		handler := consensus.ValidationRequestHandler(valAddr)

		for _, raw := range strings.Split(cfg.Consensus.Targets, ",") {
			target := strings.TrimSpace(raw)
			if target == "" {
				continue
			}
			consensusWg.Add(1)
			go func(t string) {
				defer consensusWg.Done()
				consensus.RunDialClient(ctx, t, cfg.ChainID, connKey, locked, handler, cometLogger)
			}(target)
		}
		logger.Info("consensus signer started",
			"chain_id", cfg.ChainID,
			"targets", cfg.Consensus.Targets,
		)
	}

	// Build gRPC server credentials (TLS or insecure).
	var creds credentials.TransportCredentials
	if cfg.TLS.Insecure {
		creds = insecure.NewCredentials()
	} else {
		var tlsErr error
		creds, tlsErr = bridgetls.NewServerCredentials(
			cfg.TLS.CACert,
			cfg.TLS.ServerCert,
			cfg.TLS.ServerKey,
		)
		if tlsErr != nil {
			return fmt.Errorf("build TLS credentials: %w", tlsErr)
		}
	}

	// Build and register the gRPC server.
	srv := server.New(s, logger, server.Config{
		ListenAddr:     cfg.Server.ListenAddr,
		RequestTimeout: cfg.Server.RequestTimeout,
		MaxRecvMsgSize: cfg.Server.MaxRecvMsgSize,
		Credentials:    creds,
		ChainID:        cfg.ChainID,
	})
	healthChecker := health.New(s, logger, cfg.Server.HealthAddr)

	// Log startup confirms config loaded correctly before we start serving.
	logger.AuditStartup(string(cfg.Signer.Backend), cfg.Server.ListenAddr)

	type serverExit struct {
		name string
		err  error
	}
	errCh := make(chan serverExit, 2)

	go func() {
		errCh <- serverExit{name: "health", err: healthChecker.Start()}
	}()
	go func() {
		errCh <- serverExit{name: "grpc", err: srv.Start()}
	}()

	var shutdownReason error
	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig.String())
	case exit := <-errCh:
		if exit.err != nil {
			logger.Error("server exited unexpectedly, shutting down", "server", exit.name, "error", exit.err)
			shutdownReason = fmt.Errorf("%s server: %w", exit.name, exit.err)
		} else {
			logger.Info("server exited cleanly, shutting down", "server", exit.name)
		}
	}

	ctxCancel()        // stop consensus dial goroutines

	consensusWg.Wait() // wait for all consensus goroutines to exit before shutting down gRPC

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	doneCh := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			srv.Stop()
		}()
		go func() {
			defer wg.Done()
			healthChecker.Stop(shutdownCtx)
		}()
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		logger.Info("shutdown complete")
	case <-shutdownCtx.Done():
		logger.Warn("shutdown timeout exceeded; exiting", "timeout", shutdownTimeout)
	case sig := <-sigCh:
		logger.Warn("second signal received; forcing exit", "signal", sig.String())
		return errors.New("forced exit on second signal")
	}

	return shutdownReason
}
