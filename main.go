package main

import (
	"crypto/ecdsa"
	"math/big"
)

func main() {
	// TODO input public key via command line and verify signature
}

func isSignatureValid(pubKey *ecdsa.PublicKey, messageHash []byte, r *big.Int, s *big.Int) bool {
	return ecdsa.Verify(pubKey, messageHash, r, s)
}
