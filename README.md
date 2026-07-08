# bridge-signer

A signing sidecar for TellorLayer validators. It isolates the validator's
keys from the node process and serves two signing planes:

- **Bridge signing (secp256k1)** — oracle attestations, valset checkpoints,
  and scoped transaction signing over an mTLS-secured gRPC API.
- **Consensus signing (Ed25519, optional)** — CometBFT block signing
  (votes/proposals) over the privval protocol, with double-sign protection
  and optional active-passive failover across redundant nodes.

> [!WARNING]
> This project is under active development. It has not received an external
> security audit and test coverage is still evolving, so evaluate it carefully
> and try it on a testnet before trusting it with mainnet keys.

## Architecture

```
validator node (layer)                          bridge-signer
┌──────────────────────────┐            ┌─────────────────────────────────────┐
│ VoteExtHandler ──────────┼── gRPC ───►│ BridgeSigner gRPC service           │
│                          │   mTLS     │   ├── SignOracleAttestation         │
│ CometBFT                 │            │   ├── SignBridgeCheckpoint          │
│   priv_validator_laddr ◄─┼── TCP ─────┤   ├── SignTx (msg-type allowlist)   │
│                          │  SecretConn│   ├── GetPublicKey / GetAddress /   │
└──────────────────────────┘            │   │   GetChainID                    │
                                        │   └── Sign / SignRaw (hard-disabled)│
reporter ─────────────────────gRPC ────►│                                     │
                              mTLS      │ consensus privval client (dials out)│
                                        │                                     │
                                        │ signing backends (secp256k1)        │
                                        │   ├── file (encrypted cosmos-sdk    │
                                        │   │         keyring)                │
                                        │   └── fortanixdsm                   │
                                        └─────────────────────────────────────┘
```

The gRPC plane is dialed *into* by the validator and reporter; the consensus
plane dials *out* from the signer to each node's `priv_validator_laddr`.

## Security model

Authorization is by **operation**, not by client identity: mTLS secures the
transport, but the client-cert CN is not consulted. The signer is capable of
exactly four operations:

1. **Oracle attestations** (`SignOracleAttestation`) — the signer receives the
   structured attestation inputs (never a blind hash), recomputes the snapshot
   with the byte-exact node encoder, checks it against the caller's expected
   snapshot, and fails closed (signs nothing) on any mismatch.
2. **Valset checkpoints** (`SignBridgeCheckpoint`) — same recompute-and-verify
   scheme, plus self-membership checks and a monotonic replay guard: the last
   signed `validator_timestamp` is persisted so a replayed or out-of-order
   checkpoint can never be re-signed, even across restarts.
3. **Consensus block signing** (privval) — protected by the standard
   `priv_validator_state.json` high-water mark. The daemon refuses to start if
   the state file is missing rather than silently fresh-starting (a double-sign
   risk); a brand-new signer is bootstrapped once with `init-state`.
4. **Transaction signing** (`SignTx`) — every message `type_url` in the
   SignDoc must be on the configured allowlist; an empty allowlist rejects
   everything.

The blind primitives `Sign` (65-byte, Ethereum-style) and `SignRaw` (64-byte,
Cosmos-style) are **hard-disabled in code** — they always return
`Unimplemented` and cannot be re-enabled by configuration.

Keys are encrypted at rest: the file backend stores the bridge key in a
cosmos-sdk **file keyring** (passphrase-protected), not as plaintext hex.

## Requirements

- Go 1.25+
- Linux/macOS only (the build is gated on Unix: key secrecy relies on POSIX
  file modes)
- `protoc` — only for regenerating proto code; generated code is checked in
  under `api/gen`

## Build

```bash
make build
# binary at ./bin/bridge-signer
```

Or with Docker:

```bash
docker build -t bridge-signer .
```

## Key management

Bridge keys live in a cosmos-sdk file keyring. All `keys` commands require
`--keyring-dir` and prompt for the keyring passphrase.

```bash
# Generate a new key (or restore: add --recover, or keys import-hex)
./bin/bridge-signer keys add my-bridge-key --keyring-dir /etc/bridge-signer/keyring

# Inspect
./bin/bridge-signer keys show my-bridge-key --keyring-dir /etc/bridge-signer/keyring
./bin/bridge-signer keys list --keyring-dir /etc/bridge-signer/keyring

# Export the raw hex private key (e.g. to import into FortanixDSM).
# Writes a 0600 file, refuses to overwrite, refuses to print to a terminal.
./bin/bridge-signer keys export my-bridge-key \
  --keyring-dir /etc/bridge-signer/keyring \
  --output /path/to/bridge.key.hex
```

Only the `file` keyring backend is supported (`os`, `pass`, `test`, etc. are
rejected), and the cosmos-sdk `export`/`import`/`migrate` subcommands are
removed in favor of the hardened `export` above.

## TLS certificates (dev)

```bash
mkdir tls

# CA
openssl genrsa -out tls/ca.key 4096
openssl req -new -x509 -days 365 -key tls/ca.key -out tls/ca.crt -subj "/CN=bridge-signer-ca"

# Server (sidecar)
openssl genrsa -out tls/server.key 4096
openssl req -new -key tls/server.key -out tls/server.csr -subj "/CN=bridge-signer"
openssl x509 -req -days 365 -in tls/server.csr -CA tls/ca.crt -CAkey tls/ca.key -CAcreateserial -out tls/server.crt

# Client (validator / reporter)
openssl genrsa -out tls/client.key 4096
openssl req -new -key tls/client.key -out tls/client.csr -subj "/CN=tellor-validator"
openssl x509 -req -days 365 -in tls/client.csr -CA tls/ca.crt -CAkey tls/ca.key -CAcreateserial -out tls/client.crt
```

For deployments inside a private network (e.g. a Docker compose network),
TLS can be disabled entirely with `tls.insecure: true`.

## Configuration

See [config/config.example.yaml](config/config.example.yaml) for all options
with comments.

```yaml
# Cosmos chain ID. Top-level (not under consensus) because it is also served
# via GetChainID. Required when consensus signing is enabled.
chain_id: layertest-5

signer:
  backend: file                                # file | fortanixdsm

  # --- file backend ---
  keyring_dir: /etc/bridge-signer/keyring
  key_name: my-bridge-key
  # password_file: /etc/bridge-signer/pw      # keyring passphrase, mode 0600;
                                               # required for headless runs,
                                               # otherwise prompted on stdin

  # --- fortanixdsm backend ---
  # dsm_api_endpoint: https://amer.smartkey.io
  # dsm_api_key: your-api-key
  # dsm_key_id: your-key-id (UUID)
  # dsm_key_name: my-bridge-key

server:
  listen_addr: "0.0.0.0:9191"                  # gRPC
  health_addr: "0.0.0.0:9192"                  # HTTP health/metrics
  request_timeout: 2s
  max_recv_msg_size: 1048576                   # 1MB

  # Allowlist of Cosmos message type_urls SignTx accepts. Empty => SignTx
  # rejects everything.
  allowed_msg_types:
    - /layer.oracle.MsgSubmitValue
    - /cosmos.slashing.v1beta1.MsgUnjail
    - /layer.reporter.MsgUnjailReporter

  # Turn individual RPCs off without a rebuild (false => Unimplemented).
  # The blind primitives sign/sign_raw are always disabled regardless.
  # enabled_rpcs:
  #   sign_tx: false

  # Path backing the SignBridgeCheckpoint replay guard. Defaults to
  # bridge_checkpoint_state.json next to consensus.state_file.
  # checkpoint_guard_state_file: /data/bridge_checkpoint_state.json

  # gRPC server reflection — lets any client enumerate the signing RPCs.
  # Keep false in production.
  enable_reflection: false

tls:
  ca_cert:     /etc/bridge-signer/tls/ca.crt   # verifies client certs (mTLS)
  server_cert: /etc/bridge-signer/tls/server.crt
  server_key:  /etc/bridge-signer/tls/server.key
  # insecure: true                             # disable TLS (private networks only)

logging:
  level: info                                  # debug | info | warn | error
  format: json                                 # json | text

# Optional: CometBFT consensus (privval) signing. Omit key_file to disable.
consensus:
  key_file: /keys/priv_validator_key.json      # node's Ed25519 consensus key
  state_file: /data/priv_validator_state.json  # double-sign high-water mark
  conn_key_file: /data/connection.key          # SecretConnection identity
                                               # (auto-generated if missing)
  targets: tcp://layer:26659,tcp://layer-backup:26659
  # primary_failover_timeout: 60s              # enable active-passive signing
```

## Consensus (privval) signing

When `consensus.key_file` is set, the signer holds the validator's Ed25519
consensus key and dials out to each comma-separated target — the
`priv_validator_laddr` of a CometBFT node — over TCP + SecretConnection,
serving vote/proposal sign requests and reconnecting with backoff on
disconnect.

**Bootstrap.** `start` never creates the consensus state file: a missing file
aborts startup instead of silently resetting the double-sign guard. For a
brand-new signer, create a fresh zero state once:

```bash
./bin/bridge-signer init-state --config config.yaml
```

`init-state` refuses to overwrite an existing state file. When migrating an
existing validator, copy the node's current `priv_validator_state.json` to the
signer instead of running `init-state`.

**Multiple nodes.** With several targets sharing one validator key:

- *Active-active* (default): every node's requests are served, serialized
  through the shared last-sign state, which refuses to sign conflicting data
  for a height/round/step it has already signed.
- *Active-passive*: set `primary_failover_timeout` and only one node (the
  primary) is signed for at a time. If the primary sends no sign request for
  that long, the next node to ask takes over. This avoids two live nodes
  racing the signer; the state-file check remains the ultimate backstop.

## Run

```bash
cp config/config.example.yaml config.yaml
# edit config.yaml with your paths

./bin/bridge-signer start --config ./config.yaml
```

With the file backend, `start` prompts for the keyring passphrase unless
`signer.password_file` is set (required when running as a daemon/container).

## gRPC API

Defined in [api/proto/signer/v1/signer.proto](api/proto/signer/v1/signer.proto)
(the `api/` directory is a standalone Go module for client imports).

| RPC | Purpose | Status |
|---|---|---|
| `SignOracleAttestation` | Recompute attestation snapshot from structured inputs, verify, sign | enabled |
| `SignBridgeCheckpoint` | Recompute valset checkpoint, verify, replay-guard, sign | enabled |
| `SignTx` | Sign a Cosmos SignDoc after checking every msg type against the allowlist | enabled (scoped) |
| `GetPublicKey` | Compressed 33-byte secp256k1 public key | enabled |
| `GetAddress` | Bech32 address for a given prefix (e.g. `tellor`) | enabled |
| `GetChainID` | The configured chain ID | enabled |
| `Sign` | Blind 65-byte signature over a 32-byte hash | **hard-disabled** |
| `SignRaw` | Blind 64-byte signature over a 32-byte hash | **hard-disabled** |

Enabled RPCs can be individually switched off via `server.enabled_rpcs`
(they return `Unimplemented`); the blind primitives cannot be switched on.

## Health and metrics

The HTTP server on `server.health_addr` (keep it off the public internet)
serves:

- `GET /healthz` — liveness: process is alive
- `GET /readyz` — readiness: signing backend can serve the public key
- `GET /metrics` — Prometheus; exposes a single `up` gauge so a scraper can
  alert on the signer being down

## Validator configuration

For bridge signing, enable the remote signer on the validator node:

```bash
layerd start \
  --remote-signer-enabled \
  --remote-signer-addr localhost:9191 \
  --remote-signer-ca-cert /path/to/ca.crt \
  --remote-signer-client-cert /path/to/client.crt \
  --remote-signer-client-key /path/to/client.key \
  --remote-signer-server-name bridge-signer
```

Without `--remote-signer-enabled`, the validator uses the local keyring for
bridge signing.

For consensus signing, point the node at the signer by setting
`priv_validator_laddr = "tcp://0.0.0.0:26659"` in the node's CometBFT
`config.toml` (and remove the consensus key from the node); the signer dials
in and serves sign requests.

## Development

```bash
# Regenerate proto code after editing api/proto (install tools once with
# `make proto-tools`; make sure $GOPATH/bin is in your PATH)
make proto

# Tests
go test -race ./...
```
