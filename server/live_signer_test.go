package server_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	signerv1 "github.com/tellor-io/bridge-remote-signer/api/gen/signer/v1"
	bridgetls "github.com/tellor-io/bridge-remote-signer/api/tls"
)

// Live-signer test mode.
//
// When SIGNER_URL is set, the protection tests run against that already-running
// signer instead of an in-process bootstrap, so the same "rejects all dangerous
// txs" suite can be pointed at the real mainnet signer to confirm it is hardened:
//
//	SIGNER_URL=51.81.85.117:8891 \
//	MTLS_LOCATION=/home/cryptoriums/layer-config/secrets/mtls \
//	go test ./server -run 'SignRaw_Disabled|Sign_Disabled|SignTx_BlockedMsg|SignTx_EmptySignDoc|SignTx_ZeroMessages' -v
//
// Env vars:
//   - SIGNER_URL          gRPC address of the live signer (host:port). Empty => bootstrap.
//   - MTLS_LOCATION       dir holding ca.crt, client.crt, client.key. Required when SIGNER_URL is set.
//   - SIGNER_SERVER_NAME  TLS server name to verify against (default "bridge-signer").
//
// Tests that assert golden-key or server-side-config specifics (signature
// recovery to the golden key, the golden attestation vector, a fixed chain ID,
// the empty-allowlist path) cannot hold against a real signer and are skipped in
// live mode via skipIfLive — only the operation-level protection guarantees run.

// liveSignerEnv reports the live-signer target from the environment. live is
// true when SIGNER_URL is non-empty.
func liveSignerEnv() (url, mtlsDir string, live bool) {
	url = strings.TrimSpace(os.Getenv("SIGNER_URL"))
	mtlsDir = strings.TrimSpace(os.Getenv("MTLS_LOCATION"))
	return url, mtlsDir, url != ""
}

// skipIfLive skips a test that can only pass against the in-process bootstrap
// server (golden-key or server-side-config assertions).
func skipIfLive(t *testing.T, reason string) {
	t.Helper()
	if _, _, live := liveSignerEnv(); live {
		t.Skipf("skipping against live signer: %s", reason)
	}
}

// dialLiveSigner dials the live signer named by SIGNER_URL using the mTLS
// material in MTLS_LOCATION. Returns ok=false when SIGNER_URL is unset so callers
// fall back to the in-process bootstrap.
func dialLiveSigner(t *testing.T) (client signerv1.BridgeSignerClient, cleanup func(), ok bool) {
	t.Helper()
	url, mtlsDir, live := liveSignerEnv()
	if !live {
		return nil, nil, false
	}
	if mtlsDir == "" {
		t.Fatal("SIGNER_URL is set but MTLS_LOCATION is empty; need a dir with ca.crt, client.crt, client.key")
	}

	serverName := strings.TrimSpace(os.Getenv("SIGNER_SERVER_NAME"))
	if serverName == "" {
		serverName = "bridge-signer"
	}

	creds, err := bridgetls.NewClientCredentials(
		filepath.Join(mtlsDir, "ca.crt"),
		filepath.Join(mtlsDir, "client.crt"),
		filepath.Join(mtlsDir, "client.key"),
		serverName,
	)
	if err != nil {
		t.Fatalf("live signer mTLS creds from %s: %v", mtlsDir, err)
	}

	conn, err := grpc.NewClient(url, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("dial live signer %s: %v", url, err)
	}

	t.Logf("running against LIVE signer %s (server name %q, mTLS %s)", url, serverName, mtlsDir)
	return signerv1.NewBridgeSignerClient(conn), func() { _ = conn.Close() }, true
}
