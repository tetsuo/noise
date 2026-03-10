package noisehandshake

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	// DiffieHellmanLength is the Diffie-Hellman output length.
	DiffieHellmanLength = 32
	// PublicKeyLength is the public key length.
	PublicKeyLength = 32
	// SecretKeyLength is the secret key length.
	SecretKeyLength = 32
	// DiffieHellmanAlgorithm is the DH algorithm name.
	DiffieHellmanAlgorithm = "25519"
)

// KeyPair is a Curve25519 key pair.
type KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

// Curve represents the Curve25519 DH operations.
type Curve struct{}

// DefaultCurve is the default Curve25519 implementation.
var DefaultCurve = &Curve{}

// GenerateKeyPair creates a new Curve25519 key pair.
// If privKey is provided, it derives the public key from it.
// For deterministic key generation, pass a 32-byte seed as privKey.
func (c *Curve) GenerateKeyPair(privKey []byte) (*KeyPair, error) {
	secretKey := make([]byte, SecretKeyLength)

	if privKey != nil {
		if len(privKey) != SecretKeyLength {
			return nil, fmt.Errorf("noise: invalid private key length %d, expected %d", len(privKey), SecretKeyLength)
		}
		copy(secretKey, privKey)
	} else {
		// Generate random secret key
		if _, err := io.ReadFull(rand.Reader, secretKey); err != nil {
			return nil, fmt.Errorf("noise: failed to generate random key: %w", err)
		}
	}

	// Calculate public key: publicKey = basePoint * secretKey
	// curve25519.X25519 handles the clamping internally
	publicKey, err := curve25519.X25519(secretKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("noise: X25519 operation failed: %w", err)
	}

	return &KeyPair{
		PublicKey: publicKey,
		SecretKey: secretKey,
	}, nil
}

// DH performs Diffie-Hellman calculation.
// It takes the remote party's public key and the local party's key pair,
// and returns the shared secret.
func (c *Curve) DH(publicKey []byte, localKey *KeyPair) ([]byte, error) {
	if len(publicKey) != PublicKeyLength {
		return nil, fmt.Errorf("noise: invalid public key length %d, expected %d", len(publicKey), PublicKeyLength)
	}
	if len(localKey.SecretKey) != SecretKeyLength {
		return nil, fmt.Errorf("noise: invalid secret key length %d, expected %d", len(localKey.SecretKey), SecretKeyLength)
	}

	// Perform scalar multiplication: output = secretKey * publicKey
	sharedSecret, err := curve25519.X25519(localKey.SecretKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("noise: DH calculation failed: %w", err)
	}

	return sharedSecret, nil
}

func (c *Curve) ALG() string {
	return DiffieHellmanAlgorithm
}
