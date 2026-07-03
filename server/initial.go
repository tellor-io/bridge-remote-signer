package server

import (
	"crypto/sha256"
	"fmt"
)

// initialRegistrationMessages returns the two fixed messages the node signs for
// one-time validator EVM-key registration.
func initialRegistrationMessages(operatorAddress string) (msgA, msgB string) {
	msgA = fmt.Sprintf("TellorLayer: Initial bridge signature A for operator %s", operatorAddress)
	msgB = fmt.Sprintf("TellorLayer: Initial bridge signature B for operator %s", operatorAddress)
	return msgA, msgB
}

// initialSigningDigest is the 32-byte digest actually signed for a registration
// message: sha256(sha256(message)).
func initialSigningDigest(message string) [32]byte {
	first := sha256.Sum256([]byte(message))
	return sha256.Sum256(first[:])
}
