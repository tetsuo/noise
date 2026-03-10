package noisehandshake

import (
	"crypto/hmac"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
)

const (
	hashLen = 64
)

// newBLAKE2b512 returns a new BLAKE2b-512 hash.
func newBLAKE2b512() hash.Hash {
	h, err := blake2b.New512(nil)
	if err != nil {
		panic(fmt.Sprintf("noisehandshake: could not create BLAKE2b-512 hash: %v", err))
	}
	return h
}

// hkdf performs HMAC-based Extract-and-Expand Key Derivation Function.
// Returns numChunks of hashLen-sized outputs.
func hkdf(salt, inputKeyMaterial, info []byte, numChunks int) [][]byte {
	// Extract phase: PRK = HMAC-Hash(salt, ikm)
	extractMac := hmac.New(newBLAKE2b512, salt)
	extractMac.Write(inputKeyMaterial)
	prk := extractMac.Sum(nil)

	// Expand phase: generate numChunks outputs
	results := make([][]byte, numChunks)
	var lastChunk []byte

	for i := range numChunks {
		expandMac := hmac.New(newBLAKE2b512, prk)

		// T(i) = HMAC(PRK, T(i-1) || info || i)
		if lastChunk != nil {
			expandMac.Write(lastChunk)
		}
		expandMac.Write(info)
		expandMac.Write([]byte{byte(i + 1)})

		lastChunk = expandMac.Sum(nil)
		results[i] = lastChunk
	}

	return results
}
