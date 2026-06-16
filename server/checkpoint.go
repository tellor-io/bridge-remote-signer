package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// MainnetChainID is the cosmos chain ID for which the bridge checkpoint domain
// separator is the fixed Solidity constant rather than a keccak256 of the
// (string,string) ABI encoding. Mirrors the node's mainnet branch in
// x/bridge/keeper SetValsetCheckpointDomainSeparator.
const MainnetChainID = "tellor-1"

// bridgeValidator is the structured validator-set entry used by the checkpoint
// encoder. EthereumAddress is the raw 20-byte EVM address.
type bridgeValidator struct {
	EthereumAddress []byte
	Power           uint64
}

// sortBridgeValidators applies the node's canonical sort to the validator set
// in place: primary power descending, ties broken by ascending address bytes.
// Mirrors x/bridge/keeper keeper.go:204-211. The signer must NOT trust caller
// ordering, so it always re-sorts before encoding.
func sortBridgeValidators(vs []bridgeValidator) {
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Power == vs[j].Power {
			return bytes.Compare(vs[i].EthereumAddress, vs[j].EthereumAddress) < 0
		}
		return vs[i].Power > vs[j].Power
	})
}

// encodeAndHashValidatorSet is a byte-exact port of the node's
// EncodeAndHashValidatorSet (x/bridge/keeper keeper.go:534-592). It hand-rolls
// the Solidity dynamic-array ABI encoding of Validator[]{address,uint256}:
//
//	offsetToData(32) || arrayLength(32) || [ pad(addr)(32) || power(32) ]...
//
// then keccak256s the result. The input slice MUST already be sorted in node
// canonical order.
func encodeAndHashValidatorSet(vs []bridgeValidator) (encoded, hash []byte, err error) {
	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("abi address type: %w", err)
	}
	uintType, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("abi uint256 type: %w", err)
	}
	valArgs := abi.Arguments{{Type: addressType}, {Type: uintType}}

	// offsetToData = 32 (the data follows offset+length, i.e. at byte 64).
	offsetToData := make([]byte, 32)
	binary.BigEndian.PutUint64(offsetToData[24:], uint64(32))

	// lengthEncoded = len(validators).
	lengthEncoded := make([]byte, 32)
	binary.BigEndian.PutUint64(lengthEncoded[24:], uint64(len(vs)))

	var encodedVals []byte
	for _, v := range vs {
		// common.BytesToAddress right-aligns into 20 bytes, matching the node.
		addr := common.BytesToAddress(v.EthereumAddress)
		power := new(big.Int).SetUint64(v.Power)
		encodedVal, err := valArgs.Pack(addr, power)
		if err != nil {
			return nil, nil, fmt.Errorf("pack validator: %w", err)
		}
		encodedVals = append(encodedVals, encodedVal...)
	}

	finalEncoded := append(offsetToData, lengthEncoded...)
	finalEncoded = append(finalEncoded, encodedVals...)

	return finalEncoded, crypto.Keccak256(finalEncoded), nil
}

// computeDomainSeparator recomputes the checkpoint domain separator from the
// chain ID exactly as the node does in SetValsetCheckpointDomainSeparator
// (keeper.go:136-162):
//   - mainnet: 32-byte word, ascii "checkpoint" right-padded with zeros (NOT hashed).
//   - non-mainnet: keccak256(abi.encode(string("checkpoint"), string(chainID))).
func computeDomainSeparator(chainID string) ([]byte, error) {
	if chainID == MainnetChainID {
		ds := make([]byte, 32)
		copy(ds, []byte("checkpoint"))
		return ds, nil
	}

	stringType, err := abi.NewType("string", "", nil)
	if err != nil {
		return nil, fmt.Errorf("abi string type: %w", err)
	}
	args := abi.Arguments{{Type: stringType}, {Type: stringType}}
	encoded, err := args.Pack("checkpoint", chainID)
	if err != nil {
		return nil, fmt.Errorf("pack domain separator: %w", err)
	}
	return crypto.Keccak256(encoded), nil
}

// encodeValsetCheckpoint is a byte-exact port of the node's
// EncodeValsetCheckpoint (keeper.go:410-468). It ABI-encodes
// (bytes32 domainSep, uint256 powerThreshold, uint256 validatorTimestamp,
// bytes32 validatorSetHash) — all static, a plain 4x32 concatenation — then
// keccak256s it. validatorTimestamp is in UNIX MILLISECONDS.
func encodeValsetCheckpoint(domainSep []byte, powerThreshold, validatorTimestamp uint64, validatorSetHash []byte) ([]byte, error) {
	var domainSepFixed [32]byte
	copy(domainSepFixed[:], domainSep)

	var valsetHashFixed [32]byte
	copy(valsetHashFixed[:], validatorSetHash)

	powerThresholdBig := new(big.Int).SetUint64(powerThreshold)
	validatorTimestampBig := new(big.Int).SetUint64(validatorTimestamp)

	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, fmt.Errorf("abi bytes32 type: %w", err)
	}
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, fmt.Errorf("abi uint256 type: %w", err)
	}

	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: uint256Type},
		{Type: uint256Type},
		{Type: bytes32Type},
	}
	encoded, err := args.Pack(domainSepFixed, powerThresholdBig, validatorTimestampBig, valsetHashFixed)
	if err != nil {
		return nil, fmt.Errorf("pack checkpoint: %w", err)
	}

	return crypto.Keccak256(encoded), nil
}
