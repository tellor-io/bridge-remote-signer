# bridge-signer

A lightweight secp256k1 signing sidecar for TellorLayer validators.

Holds the bridge signing key in isolation from the validator process and serves
synchronous signing requests over a mTLS-secured gRPC connection.

## Architecture

```
validator node (layer)
    └── VoteExtHandler
            └── VoteExtensionSigner (gRPC client)
                    │  mTLS
                    ▼
            bridge-signer
                    └── signer backend
                            ├── file     (soft-sign)
                            ├── fortanixdsm 
                            └── yubihsm  
```

## Requirements

- Go 1.24+
- protoc (for regenerating proto files only)
- YubiHSM2 SDK (only if building with `make build-yubihsm`)

## Setup

### 1. Install proto tools (once)

```bash
make proto-tools
# make sure $GOPATH/bin is in your PATH
export PATH="$PATH:$(go env GOPATH)/bin"
```

### 2. Generate proto code

```bash
make proto
```

### 3. Build

```bash
# Standard build (file + fortanixdsm backends)
make build

# With YubiHSM2 support (requires libyubihsm-dev)
make build-yubihsm

# binary at ./bin/bridge-signer
```

### 4. Generate a signing key (file backend)

```bash
# Generate a new secp256k1 key
./bin/bridge-signer --keygen --out /path/to/bridge.key

# Verify the key — prints compressed public key and Ethereum address
./bin/bridge-signer --pubkey --key /path/to/bridge.key
```

### 5. Generate TLS certificates (dev)

```bash
# CA
mkdir tls
cd tls
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key tls/ca.key -out tls/ca.crt -subj "/CN=bridge-signer-ca"

# Server (sidecar)
openssl genrsa -out tls/server.key 4096
openssl req -new -key tls/server.key -out tls/server.csr -subj "/CN=bridge-signer"
openssl x509 -req -days 365 -in tls/server.csr -CA tls/ca.crt -CAkey tls/ca.key -CAcreateserial -out tls/server.crt

# Client (validator)
openssl genrsa -out tls/client.key 4096
openssl req -new -key tls/client.key -out tls/client.csr -subj "/CN=tellor-validator"
openssl x509 -req -days 365 -in tls/client.csr -CA tls/ca.crt -CAkey tls/ca.key -CAcreateserial -out tls/client.crt
```

### 6. Run

```bash
cp config.example.yaml config.yaml
# edit config.yaml with your paths

./bin/bridge-signer --config ./config.yaml
```

## Configuration

See [config.example.yaml](config.example.yaml) for all options with comments.

```yaml
signer:
  backend: file                              # file | fortanixdsm | yubihsm
  key_path: /path/to/bridge.key             # file backend

  # dsm_api_endpoint: https://amer.smartkey.io
  # dsm_api_key: your-api-key
  # dsm_key_id: your-key-id (UUID format)
  # dsm_key_name: my-bridge-key

  # yubihsm_adapter: usb                    # yubihsm backend
  # yubihsm_auth_key_id: 4                
  # yubihsm_password_file: /path/to/pw
  # yubihsm_key_id: 1

server:
  listen_addr: "0.0.0.0:9191"
  health_addr: "0.0.0.0:9192"
  request_timeout: 2s

tls:
  ca_cert:     /path/to/ca.crt
  server_cert: /path/to/server.crt
  server_key:  /path/to/server.key

logging:
  level: info       # debug | info | warn | error
  format: json      # json | text
```

## Signing Backends

| Backend | Key location |
|---------|-------------|
| `file` | Hex file on disk |
| `fortanixdsm` | FortanixDSM |
| `yubihsm` | YubiHSM2 hardware device |

The YubiHSM2 backend supports direct USB access via `libyubihsm` (no
`yubihsm-connector` daemon required) and follows the same role-based
authentication model as [TMKMS](https://github.com/iqlusioninc/tmkms).

## Validator Configuration

On the validator node, enable the remote signer with these flags:

```bash
layerd start \
  --remote-signer-enabled \
  --remote-signer-addr localhost:9191 \
  --remote-signer-ca-cert /path/to/ca.crt \
  --remote-signer-client-cert /path/to/client.crt \
  --remote-signer-client-key /path/to/client.key \
  --remote-signer-server-name bridge-signer
```

Without `--remote-signer-enabled`, the validator uses the local keyring
for bridge signing.
