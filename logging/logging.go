package logging

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Logger wraps slog.Logger with audit-specific methods for the sidecar.
// Every signing operation is logged with enough context to reconstruct
// what was signed, when, and whether it succeeded
type Logger struct {
	log *slog.Logger
}

// New creates a Logger from the given level and format strings.
// level: "debug" | "info" | "warn" | "error"
// format: "json"
func New(level, format string) (*Logger, error) {
	slogLevel, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{
		Level: slogLevel,
		// Include source file and line in debug mode.
		AddSource: slogLevel == slog.LevelDebug,
	}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		return nil, fmt.Errorf("unknown log format %q (json|text)", format)
	}

	return &Logger{log: slog.New(handler)}, nil
}

// Info logs an informational message.
func (l *Logger) Info(msg string, args ...any) {
	l.log.Info(msg, args...)
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, args ...any) {
	l.log.Debug(msg, args...)
}

// Warn logs a warning.
func (l *Logger) Warn(msg string, args ...any) {
	l.log.Warn(msg, args...)
}

// Error logs an error.
func (l *Logger) Error(msg string, args ...any) {
	l.log.Error(msg, args...)
}

// AuditSign logs a signing operation.
// We log the SHA256 of the message should be enough to correlate with validator-side logs via request_id.
func (l *Logger) AuditSign(ctx context.Context, requestID string, msg []byte, err error, duration time.Duration) {
	msgHash := sha256.Sum256(msg)
	msgHashHex := hex.EncodeToString(msgHash[:])

	attrs := []any{
		"event", "sign",
		"request_id", requestID,
		"msg_hash", msgHashHex,
		"msg_len", len(msg),
		"duration_ms", duration.Milliseconds(),
	}

	if err != nil {
		attrs = append(attrs, "error", err.Error(), "success", false)
		l.log.ErrorContext(ctx, "sign request failed", attrs...)
		return
	}

	attrs = append(attrs, "success", true)
	l.log.InfoContext(ctx, "sign request completed", attrs...)
}

// AuditStartup logs the sidecar startup configuration.
func (l *Logger) AuditStartup(backend, listenAddr string) {
	l.log.Info("bridge-signer starting",
		"event", "startup",
		"backend", backend,
		"listen_addr", listenAddr,
	)
}

// AuditGetPublicKey logs a public key request.
// Logs that it was requested but not the key itself
func (l *Logger) AuditGetPublicKey(ctx context.Context, err error) {
	if err != nil {
		l.log.ErrorContext(ctx, "get public key failed",
			"event", "get_public_key",
			"error", err.Error(),
			"success", false,
		)
		return
	}
	l.log.InfoContext(ctx, "get public key",
		"event", "get_public_key",
		"success", true,
	)
}

// AuditShutdown logs graceful shutdown.
func (l *Logger) AuditShutdown() {
	l.log.Info("bridge-signer shutting down", "event", "shutdown")
}

// AuditConnection logs an incoming client connection at debug level: these are
// high-volume / noisy at info; the signing events (AuditSign etc.) are the ones
// worth surfacing at info.
func (l *Logger) AuditConnection(remoteAddr string) {
	l.log.Debug("client connected",
		"event", "connection",
		"remote_addr", remoteAddr,
	)
}

// parseLevel converts a string level to slog.Level.
func parseLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q (debug|info|warn|error)", level)
	}
}
