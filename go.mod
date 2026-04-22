module github.com/tellor-io/bridge-remote-signer

go 1.25.9

require (
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/ethereum/go-ethereum v1.17.1
	github.com/fortanix/sdkms-client-go v0.4.1
	github.com/tellor-io/bridge-remote-signer/api v0.0.0
	golang.org/x/crypto v0.46.0
	golang.org/x/term v0.38.0
	google.golang.org/grpc v1.79.3
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251222181119-0a764e51fe1b // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace github.com/tellor-io/bridge-remote-signer/api => ./api
