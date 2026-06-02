package consensus

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/privval"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	"github.com/cometbft/cometbft/types"
)

// MaxRemoteSignerMsgSize is the max decoded privval frame (CometBFT default).
const MaxRemoteSignerMsgSize = 1024 * 10

// RunDialClient maintains a TCP+SecretConnection to a CometBFT node's
// priv_validator_laddr and serves privval requests until disconnect, then
// reconnects. Multiple RunDialClient goroutines may share the same PrivValidator
// if it is wrapped with LockedPrivValidator.
func RunDialClient(
	ctx context.Context,
	targetAddr string,
	chainID string,
	connPrivKey crypto.PrivKey,
	pv types.PrivValidator,
	handler privval.ValidationRequestHandlerFunc,
	logger log.Logger,
) {
	dialer := privval.DialTCPFn(targetAddr, 8*time.Second, connPrivKey)
	runDialClient(ctx, dialer, chainID, pv, handler, logger.With("remote", targetAddr))
}

// runDialClient is the internal implementation that accepts an injectable dial
// function. Used directly in tests.
func runDialClient(
	ctx context.Context,
	dialFn func() (net.Conn, error),
	chainID string,
	pv types.PrivValidator,
	handler privval.ValidationRequestHandlerFunc,
	logger log.Logger,
) {
	const (
		minBackoff = time.Second
		maxBackoff = 5 * time.Second
	)
	backoff := minBackoff

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := dialFn()
		if err != nil {
			logger.Error("privval dial failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff: 1s → 2s → 4s … capped at 5s
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		logger.Info("privval connected")
		backoff = minBackoff // reset on successful connection
		serveConn(ctx, conn, chainID, pv, handler, logger)
		_ = conn.Close()
		logger.Info("privval connection closed, reconnecting")

		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// serveConn handles one privval connection until disconnect or ctx cancellation.
// A goroutine closes conn when ctx is done so rd.ReadMsg() unblocks promptly.
func serveConn(
	ctx context.Context,
	conn net.Conn,
	chainID string,
	pv types.PrivValidator,
	handler privval.ValidationRequestHandlerFunc,
	logger log.Logger,
) {
	// Close conn on context cancellation to unblock any blocking read.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	rd := protoio.NewDelimitedReader(conn, MaxRemoteSignerMsgSize)
	wr := protoio.NewDelimitedWriter(conn)
	deadline := 10 * time.Second

	for {
		_ = conn.SetReadDeadline(time.Now().Add(deadline))
		var req privvalproto.Message
		_, err := rd.ReadMsg(&req)
		if err != nil {
			if err != io.EOF && ctx.Err() == nil {
				logger.Error("privval read", "err", err)
			}
			return
		}

		res, handleErr := handler(pv, req, chainID)
		if handleErr != nil {
			logger.Error("privval handler", "err", handleErr)
		}

		_ = conn.SetWriteDeadline(time.Now().Add(deadline))
		if _, err := wr.WriteMsg(&res); err != nil {
			logger.Error("privval write", "err", err)
			return
		}
	}
}
