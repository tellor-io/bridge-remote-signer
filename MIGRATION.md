# Migrating the mainnet bridge-signer to the hardened (operation-based) build

This build replaces the old "sign anything" signer with one that can perform
**only four operations**. Blind signing is removed.

## ⚠️ Deploy together with the node — do NOT update the signer alone

The hardened signer **hard-disables `SignRaw`**. The mainnet node currently
running (`ghcr.io/cryptoriums/layer:6.1.5-rs`) signs its bridge vote-extensions
via `SignRaw`, so if you point it at the hardened signer those calls are
**rejected** and the validator stops signing → it gets **jailed** (downtime).

The hardened signer must be deployed **at the same time as the `6.1.6-rs` node**,
which signs via `SignBridgeCheckpoint` / `SignOracleAttestation` instead of
`SignRaw`. The reporter must use `SignTx` (allowlist), not `SignRaw`.

Never run two signers on one consensus key (double-sign tombstone).

## What changed

- `Sign` (65-byte) and `SignRaw` (64-byte) blind primitives → **always disabled**.
- Reports + unjail → `SignTx`, scoped by `server.allowed_msg_types`.
- Attestations + valset checkpoint → `SignOracleAttestation` /
  `SignBridgeCheckpoint` (recompute-and-verify: the signer rebuilds the value
  itself and refuses to sign anything that doesn't match).
- Per-client-cert CN authorization **removed** — authorization is by OPERATION.
  mTLS is still required as transport (the client cert must chain to the CA).

## Config changes

Add to `server:` in `config.yaml` (see `config/config.example.yaml`):

```yaml
server:
  allowed_msg_types:
    - /layer.oracle.MsgSubmitValue
    - /cosmos.slashing.v1beta1.MsgUnjail
    - /layer.reporter.MsgUnjailReporter
  # enabled_rpcs:      # optional: turn an RPC off without a rebuild
  #   sign_tx: false
  enable_reflection: false
```

There are no `*_allowed_cns` knobs anymore — remove any if present.

## Deploy steps (coordinated)

1. Build/pull the hardened signer image **and** the `6.1.6-rs` node image.
2. Update the signer `config.yaml` with the `allowed_msg_types` above.
3. Stop the old signer, start the hardened signer (single instance), and
   recreate the node as `6.1.6-rs` — **together**.
4. Verify:
   - validator still signing — `missed_blocks_counter` stays 0, signing-info
     `index_offset` climbing, not jailed.
   - reporter can submit reports (`SignTx`) and unjail.
5. Rollback (if needed): revert the signer image **and** the node to `6.1.5-rs`
   together — the old node needs `SignRaw`, which the hardened signer refuses.
