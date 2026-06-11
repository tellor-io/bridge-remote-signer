package signer

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Signer is the interface that all signing backends implement.
type Signer interface {
	// Sign signs a 32-byte digest and returns a 65-byte Ethereum-format
	Sign(ctx context.Context, msg []byte) ([]byte, error)

	// SignRaw signs the given 32-byte hash directly without any additional hashing.
	// Returns a 64-byte secp256k1 ECDSA signature (r || s), without the v byte.
	// Used for Cosmos SDK tx signing where the digest is already computed by the SDK.
	SignRaw(ctx context.Context, msg []byte) ([]byte, error)

	// GetPublicKey returns the compressed 33-byte secp256k1 public key.
	GetPublicKey(ctx context.Context) ([]byte, error)
}

// NewSigner creates the appropriate signing backend based on the config.
// It looks up the backend name in the registry. If the backend wasn't
// compiled the user gets anr error explaining how to rebuild.
func NewSigner(ctx context.Context, backend string, rawConfig map[string]any) (Signer, error) {
	factory, ok := getBackendFactory(backend)
	if !ok {
		available := AvailableBackends()
		return nil, fmt.Errorf(
			"unknown signer backend %q (available: %s); "+
				"if this is a compile-time optional backend, rebuild with the appropriate -tags flag",
			backend,
			strings.Join(available, ", "),
		)
	}
	return factory(ctx, rawConfig)
}

// BackendFactory is a constructor function for a signing backend.
// Each backend registers one of these at init() time.
type BackendFactory func(ctx context.Context, raw map[string]any) (Signer, error)

// registry holds all registered backend factories.
// Backends register themselves via init() functions, so by the time
// main() runs, all compiled-in backends are available.
var (
	registryMu sync.Mutex
	registry   = make(map[string]BackendFactory)
)

// RegisterBackend registers a signing backend factory under the given name.
// This is called from init() in each backend file.
func RegisterBackend(name string, factory BackendFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("signer backend %q already registered", name))
	}
	registry[name] = factory
}

// getBackendFactory looks up a registered backend by name.
func getBackendFactory(name string) (BackendFactory, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()

	f, ok := registry[name]
	return f, ok
}

// AvailableBackends returns the names of all registered backends.
// Useful for error messages.
func AvailableBackends() []string {
	registryMu.Lock()
	defer registryMu.Unlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
