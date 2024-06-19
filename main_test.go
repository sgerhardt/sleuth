package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"testing"
)
import "github.com/stretchr/testify/assert"

func Test_verifySignature(t *testing.T) {
	type args struct {
		message   string
		publicKey func(key *ecdsa.PrivateKey) *ecdsa.PublicKey
	}

	type expected struct {
		isValid bool
	}

	tests := []struct {
		name     string
		args     args
		expected expected
	}{
		{
			"empty message, same private and public key",
			args{
				message:   "",
				publicKey: func(key *ecdsa.PrivateKey) *ecdsa.PublicKey { return &key.PublicKey },
			},
			expected{isValid: true},
		},
		{
			"non-empty message, same private and public key",
			args{
				message:   "hello world!",
				publicKey: func(key *ecdsa.PrivateKey) *ecdsa.PublicKey { return &key.PublicKey },
			},
			expected{isValid: true},
		},
		{
			"non-empty message, different private and public key",
			args{
				message: "hello world!",
				publicKey: func(key *ecdsa.PrivateKey) *ecdsa.PublicKey {
					privateKey, err := crypto.GenerateKey()
					require.NoError(t, err)
					return &privateKey.PublicKey
				},
			},
			expected{isValid: false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := crypto.GenerateKey()
			require.NoError(t, err)

			// Message to be signed
			hash := sha256.Sum256([]byte(tt.args.message))

			// Sign the message
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
			if err != nil {
				panic(err)
			}

			assert.Equal(t, tt.expected.isValid, isSignatureValid(tt.args.publicKey(privateKey), hash[:], r, s))
		})
	}
}
