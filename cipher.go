package noisehandshake

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// MaxMessageLength is the maximum Noise message size.
	MaxMessageLength = 65535
	// KeyBytes is the cipher key size. For ChaCha20Poly1305, this is 32 bytes.
	KeyBytes = 32
	// MacBytes is the MAC size.
	MacBytes = 16
)

var (
	// ErrCiphertextTooLong indicates message exceeds maximum length.
	ErrCiphertextTooLong = errors.New("ciphertext exceeds maximum message length")
	// ErrInvalidKeySize indicates invalid key size.
	ErrInvalidKeySize = errors.New("invalid key size for ChaCha20Poly1305")
)

// CipherState represents the cipher state in Noise Protocol.
type CipherState struct {
	key      []byte
	aead     cipher.AEAD // Reuse AEAD instance for performance
	nonce    uint64
	nonceBuf [chacha20poly1305.NonceSize]byte
}

// newCipherState creates a new cipher state with an optional key.
func newCipherState(key []byte) (*CipherState, error) {
	cs := &CipherState{
		nonce: 0,
	}
	if key != nil {
		if len(key) != KeyBytes {
			return nil, ErrInvalidKeySize
		}
		cs.initializeKey(key)
	}
	return cs, nil
}

// initializeKey sets the key and resets the nonce.
// This assumes key is a valid 32-byte slice. Caller should ensure this is the case.
func (cs *CipherState) initializeKey(key []byte) {
	cs.key = make([]byte, len(key))
	copy(cs.key, key)

	// Initialize the AEAD once for reuse
	var err error
	cs.aead, err = chacha20poly1305.New(cs.key)
	if err != nil {
		// Should never happen with 32-byte key
		panic(fmt.Sprintf("cipher: failed to initialize AEAD: %v", err))
	}

	cs.nonce = 0
}

// HasKey returns true if the cipher state has a key.
func (cs *CipherState) HasKey() bool {
	return cs.aead != nil
}

// Encrypt encrypts plaintext with associated data, appending the result to dst.
// If no key is set, it appends the plaintext unchanged.
func (cs *CipherState) Encrypt(dst, plaintext, ad []byte) ([]byte, error) {
	if !cs.HasKey() {
		return append(dst, plaintext...), nil
	}

	binary.LittleEndian.PutUint64(cs.nonceBuf[4:], cs.nonce)

	ret := cs.aead.Seal(dst, cs.nonceBuf[:], plaintext, ad)

	if len(ret)-len(dst) > MaxMessageLength {
		return nil, ErrCiphertextTooLong
	}

	cs.nonce++
	return ret, nil
}

// Decrypt decrypts ciphertext with associated data, appending the result to dst.
// If no key is set, it appends the ciphertext unchanged.
func (cs *CipherState) Decrypt(dst, ciphertext, ad []byte) ([]byte, error) {
	if !cs.HasKey() {
		return append(dst, ciphertext...), nil
	}

	if len(ciphertext) > MaxMessageLength {
		return nil, ErrCiphertextTooLong
	}

	binary.LittleEndian.PutUint64(cs.nonceBuf[4:], cs.nonce)

	ret, err := cs.aead.Open(dst, cs.nonceBuf[:], ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	cs.nonce++
	return ret, nil
}

// Clear clears the key from memory.
func (cs *CipherState) Clear() {
	if cs.key != nil {
		for i := range cs.key {
			cs.key[i] = 0
		}
		cs.key = nil
	}
	cs.aead = nil
	cs.nonce = 0
}

// Key returns a copy of the cipher key.
func (cs *CipherState) Key() []byte {
	if cs.key == nil {
		return nil
	}
	key := make([]byte, len(cs.key))
	copy(key, cs.key)
	return key
}
