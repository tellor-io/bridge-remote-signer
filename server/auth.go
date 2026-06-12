package server

import (
	"context"

	signerv1 "github.com/tellor-io/bridge-remote-signer/api/gen/signer/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Fully-qualified gRPC method names for the signing RPCs. Used as keys for the
// enabled-RPC gate.
const (
	MethodSign                  = signerv1.BridgeSigner_Sign_FullMethodName
	MethodSignRaw               = signerv1.BridgeSigner_SignRaw_FullMethodName
	MethodSignTx                = signerv1.BridgeSigner_SignTx_FullMethodName
	MethodSignBridgeCheckpoint  = signerv1.BridgeSigner_SignBridgeCheckpoint_FullMethodName
	MethodSignOracleAttestation = signerv1.BridgeSigner_SignOracleAttestation_FullMethodName
)

// shortRPCNameToFullMethod maps the short, config-friendly RPC names to their
// fully-qualified gRPC method names for the enabled-RPC gate.
var shortRPCNameToFullMethod = map[string]string{
	"sign_raw":                signerv1.BridgeSigner_SignRaw_FullMethodName,
	"sign_tx":                 signerv1.BridgeSigner_SignTx_FullMethodName,
	"sign_bridge_checkpoint":  signerv1.BridgeSigner_SignBridgeCheckpoint_FullMethodName,
	"sign_oracle_attestation": signerv1.BridgeSigner_SignOracleAttestation_FullMethodName,
	"sign":                    signerv1.BridgeSigner_Sign_FullMethodName,
	"get_public_key":          signerv1.BridgeSigner_GetPublicKey_FullMethodName,
	"get_address":             signerv1.BridgeSigner_GetAddress_FullMethodName,
	"get_chain_id":            signerv1.BridgeSigner_GetChainID_FullMethodName,
}

// EnabledRPCsFromConfig translates the config's short RPC-name => bool map into
// a fully-qualified-method => bool map for the enabled-RPC interceptor. Unknown
// short names are ignored. Methods absent from the result are enabled by
// default, so an empty/nil config leaves everything enabled.
func EnabledRPCsFromConfig(cfg map[string]bool) map[string]bool {
	if len(cfg) == 0 {
		return nil
	}
	out := make(map[string]bool, len(cfg))
	for name, enabled := range cfg {
		if full, ok := shortRPCNameToFullMethod[name]; ok {
			out[full] = enabled
		}
	}
	return out
}

// chainUnaryInterceptors composes interceptors left-to-right: the first runs
// outermost (its pre-handler logic runs first, its post-handler logic runs
// last). nil entries are skipped.
func chainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	filtered := make([]grpc.UnaryServerInterceptor, 0, len(interceptors))
	for _, ic := range interceptors {
		if ic != nil {
			filtered = append(filtered, ic)
		}
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		var build func(i int) grpc.UnaryHandler
		build = func(i int) grpc.UnaryHandler {
			if i == len(filtered) {
				return handler
			}
			return func(ctx context.Context, req any) (any, error) {
				return filtered[i](ctx, req, info, build(i+1))
			}
		}
		return build(0)(ctx, req)
	}
}

// newEnabledRPCInterceptor rejects (Unimplemented) any method explicitly
// disabled via the enabled map (enabled[method]==false). Methods absent from
// the map are enabled by default.
func newEnabledRPCInterceptor(enabled map[string]bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if v, ok := enabled[info.FullMethod]; ok && !v {
			return nil, status.Errorf(codes.Unimplemented, "method %s is disabled", info.FullMethod)
		}
		return handler(ctx, req)
	}
}

// KnownShortRPCNames returns the set of recognized short RPC names accepted in
// the enabled_rpcs config map. Used to reject typos at config-load time.
func KnownShortRPCNames() map[string]struct{} {
	out := make(map[string]struct{}, len(shortRPCNameToFullMethod))
	for name := range shortRPCNameToFullMethod {
		out[name] = struct{}{}
	}
	return out
}
