package server

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

// oracleAttestationDomainSeparator is the FIXED attestation domain separator the
// node hardcodes in EncodeOracleAttestationData
// (x/bridge/keeper/keeper.go ~1163): the ascii bytes "tellorCurrentAttestation"
// (24 bytes) copied into a [32]byte (front-aligned, right zero-padded). It is
// NOT hashed. The resulting bytes32 is:
//
//	74656c6c6f7243757272656e744174746573746174696f6e0000000000000000
var oracleAttestationDomainSeparator = []byte("tellorCurrentAttestation")

// encodeOracleAttestation is a byte-exact port of the node's
// EncodeOracleAttestationData (x/bridge/keeper/keeper.go ~1152-1252). It ABI-packs
// the attestation arguments with go-ethereum accounts/abi (standard head/tail
// encoding) and keccak256s the result, yielding the 32-byte snapshot (a.k.a.
// oracleAttestationHash).
//
// The arguments, IN THIS EXACT ORDER/TYPE, are:
//
//	[0] bytes32 domainSep      = "tellorCurrentAttestation" -> [32]byte (right zero-pad), NOT hashed
//	[1] bytes32 queryId        = queryId copied into [32]byte (front-aligned, right zero-pad)
//	[2] bytes   value          = the raw (already hex-decoded) value bytes, ABI dynamic bytes
//	[3] uint256 timestamp
//	[4] uint256 aggregatePower
//	[5] uint256 previousTimestamp
//	[6] uint256 nextTimestamp
//	[7] bytes32 valsetCheckpoint = copied into [32]byte (front-aligned, right zero-pad)
//	[8] uint256 attestationTimestamp
//	[9] uint256 lastConsensusTimestamp
//
// value carries the ALREADY-HEX-DECODED bytes (the node computes them via
// hex.DecodeString(Remove0xPrefix(valueString)) and passes the resulting bytes
// into the ABI pack as the dynamic `bytes` arg); the signer does no further
// decoding.
func encodeOracleAttestation(
	queryID []byte,
	value []byte,
	timestamp uint64,
	aggregatePower uint64,
	previousTimestamp uint64,
	nextTimestamp uint64,
	valsetCheckpoint []byte,
	attestationTimestamp uint64,
	lastConsensusTimestamp uint64,
) ([]byte, error) {
	// Domain separator -> bytes32 (front-aligned, right zero-pad; NOT hashed).
	var domainSepBytes32 [32]byte
	copy(domainSepBytes32[:], oracleAttestationDomainSeparator)

	// queryId -> bytes32 (front-aligned, right zero-pad if < 32 bytes).
	var queryIDBytes32 [32]byte
	copy(queryIDBytes32[:], queryID)

	// valsetCheckpoint -> bytes32 (front-aligned, right zero-pad if < 32 bytes).
	var valsetCheckpointBytes32 [32]byte
	copy(valsetCheckpointBytes32[:], valsetCheckpoint)

	// value is the already-decoded raw bytes; ABI-packed as dynamic `bytes`.
	// Copy so the packer never aliases the caller's slice.
	valueBytes := make([]byte, len(value))
	copy(valueBytes, value)

	timestampBig := new(big.Int).SetUint64(timestamp)
	aggregatePowerBig := new(big.Int).SetUint64(aggregatePower)
	previousTimestampBig := new(big.Int).SetUint64(previousTimestamp)
	nextTimestampBig := new(big.Int).SetUint64(nextTimestamp)
	attestationTimestampBig := new(big.Int).SetUint64(attestationTimestamp)
	lastConsensusTimestampBig := new(big.Int).SetUint64(lastConsensusTimestamp)

	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, fmt.Errorf("abi bytes32 type: %w", err)
	}
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, fmt.Errorf("abi uint256 type: %w", err)
	}
	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, fmt.Errorf("abi bytes type: %w", err)
	}

	arguments := abi.Arguments{
		{Type: bytes32Type}, // [0] domainSep
		{Type: bytes32Type}, // [1] queryId
		{Type: bytesType},   // [2] value (dynamic)
		{Type: uint256Type}, // [3] timestamp
		{Type: uint256Type}, // [4] aggregatePower
		{Type: uint256Type}, // [5] previousTimestamp
		{Type: uint256Type}, // [6] nextTimestamp
		{Type: bytes32Type}, // [7] valsetCheckpoint
		{Type: uint256Type}, // [8] attestationTimestamp
		{Type: uint256Type}, // [9] lastConsensusTimestamp
	}

	encodedData, err := arguments.Pack(
		domainSepBytes32,
		queryIDBytes32,
		valueBytes,
		timestampBig,
		aggregatePowerBig,
		previousTimestampBig,
		nextTimestampBig,
		valsetCheckpointBytes32,
		attestationTimestampBig,
		lastConsensusTimestampBig,
	)
	if err != nil {
		return nil, fmt.Errorf("pack oracle attestation: %w", err)
	}

	return crypto.Keccak256(encodedData), nil
}
