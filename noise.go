// Package noisehandshake implements cryptographic handshake patterns as defined
// in the Noise Protocol Framework.
package noisehandshake

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

// Token represents a handshake pattern token.
type Token int

const (
	// Preshare tokens.
	TokenPreshareIS Token = iota - 2
	TokenPreshareRS

	// Message tokens.
	TokenPSK
	TokenE
	TokenS
	TokenEE
	TokenES
	TokenSE
	TokenSS
)

// HandshakePattern defines a Noise handshake pattern.
type HandshakePattern struct {
	Name     string
	Messages [][]Token
	Preshare []Token
}

// Predefined handshake patterns.
var (
	// PatternNN is the NN handshake pattern.
	// No static keys, no pre-shared keys.
	PatternNN = &HandshakePattern{
		Name: "NN",
		Messages: [][]Token{
			{TokenE},
			{TokenE, TokenEE},
		},
	}

	// PatternNNpsk0 is the NN handshake pattern with a pre-shared key.
	// Both parties mix the PSK before sending their ephemeral key.
	PatternNNpsk0 = &HandshakePattern{
		Name: "NNpsk0",
		Messages: [][]Token{
			{TokenPSK, TokenE},
			{TokenE, TokenEE},
		},
	}

	// PatternXX is the XX handshake pattern.
	// Both parties have static keys, but they are not pre-shared.
	PatternXX = &HandshakePattern{
		Name: "XX",
		Messages: [][]Token{
			{TokenE},
			{TokenE, TokenEE, TokenS, TokenES},
			{TokenS, TokenSE},
		},
	}

	// PatternXXpsk0 is the XX handshake pattern with a pre-shared key.
	// Both parties mix the PSK before sending their ephemeral key.
	PatternXXpsk0 = &HandshakePattern{
		Name: "XXpsk0",
		Messages: [][]Token{
			{TokenPSK, TokenE},
			{TokenE, TokenEE, TokenS, TokenES},
			{TokenS, TokenSE},
		},
	}

	// PatternIK is the IK handshake pattern.
	// The initiator knows the responder's static public key in advance.
	PatternIK = &HandshakePattern{
		Name:     "IK",
		Preshare: []Token{TokenPreshareRS},
		Messages: [][]Token{
			{TokenE, TokenES, TokenS, TokenSS},
			{TokenE, TokenEE, TokenSE},
		},
	}

	// PatternXK is the XK handshake pattern.
	// The responder has a static key, but the initiator does not know it in advance.
	PatternXK = &HandshakePattern{
		Name:     "XK",
		Preshare: []Token{TokenPreshareRS},
		Messages: [][]Token{
			{TokenE, TokenES},
			{TokenE, TokenEE},
			{TokenS, TokenSE},
		},
	}
)

// NoiseState represents a Noise Protocol handshake state.
type NoiseState struct {
	*symmetricState

	// Static and ephemeral keypairs.
	s *KeyPair
	e *KeyPair

	// Remote keys.
	re []byte
	rs []byte

	// PSK. Only used if handshake pattern includes PSK token.
	psk []byte

	// Pattern and state.
	pattern        *HandshakePattern
	handshakeQueue [][]Token
	initiator      bool
	isPskHandshake bool
	complete       bool

	// Final transport keys and hash.
	tx   *CipherState
	rx   *CipherState
	hash []byte
}

// Config holds configuration for NoiseState.
type Config struct {
	Curve         *Curve
	StaticKeypair *KeyPair
	PSK           []byte
}

// NewNoiseState creates a new Noise Protocol state.
func NewNoiseState(pattern *HandshakePattern, initiator bool, config *Config) (*NoiseState, error) {
	if config == nil {
		config = &Config{}
	}
	if config.Curve == nil {
		config.Curve = DefaultCurve
	}

	// Generate static keypair if not provided
	staticKP := config.StaticKeypair
	if staticKP == nil {
		var err error
		staticKP, err = config.Curve.GenerateKeyPair(nil)
		if err != nil {
			return nil, err
		}
	}

	// Copy handshake pattern
	handshakeQueue := make([][]Token, 0)
	if pattern.Preshare != nil {
		for _, t := range pattern.Preshare {
			handshakeQueue = append(handshakeQueue, []Token{t})
		}
	}
	for _, msg := range pattern.Messages {
		msgCopy := make([]Token, len(msg))
		copy(msgCopy, msg)
		handshakeQueue = append(handshakeQueue, msgCopy)
	}

	if config.PSK != nil && len(config.PSK) != 32 {
		return nil, fmt.Errorf("noise: PSK must be exactly 32 bytes, got %d", len(config.PSK))
	}

	isPskHandshake := config.PSK != nil && hasPskToken(handshakeQueue)

	ns := &NoiseState{
		symmetricState: newSymmetricState(config.Curve),
		s:              staticKP,
		e:              nil,
		re:             nil,
		rs:             nil,
		psk:            config.PSK,
		pattern:        pattern,
		handshakeQueue: handshakeQueue,
		initiator:      initiator,
		isPskHandshake: isPskHandshake,
		complete:       false,
		tx:             nil,
		rx:             nil,
		hash:           nil,
	}

	return ns, nil
}

// Initialize initializes the handshake with prologue and optional remote static key.
func (ns *NoiseState) Initialize(prologue, remoteStatic []byte) error {
	// Build protocol name
	protocolName := fmt.Sprintf("Noise_%s_%s_%s_BLAKE2b",
		ns.pattern.Name,
		ns.curve.ALG(),
		"ChaChaPoly")

	// Initialize symmetric state with protocol name
	ns.initializeSymmetric([]byte(protocolName))

	// Mix prologue
	ns.mixHash(prologue)

	// Process preshare tokens
	for len(ns.handshakeQueue) > 0 && len(ns.handshakeQueue[0]) == 1 {
		token := ns.handshakeQueue[0][0]
		if token != TokenPreshareRS && token != TokenPreshareIS {
			break
		}

		ns.handshakeQueue = ns.handshakeQueue[1:]

		takeRemoteKey := (ns.initiator && token == TokenPreshareRS) ||
			(!ns.initiator && token == TokenPreshareIS)

		if takeRemoteKey {
			if remoteStatic == nil {
				return errors.New("remote static key required for preshare")
			}
			ns.rs = make([]byte, len(remoteStatic))
			copy(ns.rs, remoteStatic)
		}

		var key []byte
		if takeRemoteKey {
			key = ns.rs
		} else {
			key = ns.s.PublicKey
		}

		ns.mixHash(key)
	}

	return nil
}

// Send sends a handshake message with optional payload.
func (ns *NoiseState) Send(payload []byte) ([]byte, error) {
	if len(ns.handshakeQueue) == 0 {
		return nil, errors.New("handshake already complete")
	}

	if payload == nil {
		payload = []byte{}
	}

	var buf bytes.Buffer
	patterns := ns.handshakeQueue[0]
	ns.handshakeQueue = ns.handshakeQueue[1:]

	for _, token := range patterns {
		switch token {
		case TokenPSK:
			ns.mixKeyAndHash(ns.psk)

		case TokenE:
			if ns.e == nil {
				var err error
				ns.e, err = ns.curve.GenerateKeyPair(nil)
				if err != nil {
					return nil, err
				}
			}
			ns.mixHash(ns.e.PublicKey)
			if ns.isPskHandshake {
				ns.mixKeyNormal(ns.e.PublicKey)
			}
			buf.Write(ns.e.PublicKey)

		case TokenS:
			ciphertext, err := ns.encryptAndHash(ns.s.PublicKey)
			if err != nil {
				return nil, err
			}
			buf.Write(ciphertext)

		case TokenEE, TokenES, TokenSE, TokenSS:
			useStatic := getKeyPattern(token, ns.initiator)
			localKey := ns.s
			if !useStatic.local {
				localKey = ns.e
			}
			remoteKey := ns.rs
			if !useStatic.remote {
				remoteKey = ns.re
			}
			if err := ns.mixKey(remoteKey, localKey); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unexpected token: %d", token)
		}
	}

	// Encrypt payload
	ciphertext, err := ns.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	buf.Write(ciphertext)

	// Finalize if handshake complete
	if len(ns.handshakeQueue) == 0 {
		if err := ns.final(); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// Recv receives and processes a handshake message.
func (ns *NoiseState) Recv(message []byte) ([]byte, error) {
	if len(ns.handshakeQueue) == 0 {
		return nil, errors.New("handshake already complete")
	}

	offset := 0
	patterns := ns.handshakeQueue[0]
	ns.handshakeQueue = ns.handshakeQueue[1:]

	for _, token := range patterns {
		switch token {
		case TokenPSK:
			ns.mixKeyAndHash(ns.psk)

		case TokenE:
			if offset+PublicKeyLength > len(message) {
				return nil, errors.New("insufficient bytes for public key")
			}
			ns.re = make([]byte, PublicKeyLength)
			copy(ns.re, message[offset:offset+PublicKeyLength])
			offset += PublicKeyLength

			ns.mixHash(ns.re)
			if ns.isPskHandshake {
				ns.mixKeyNormal(ns.re)
			}

		case TokenS:
			klen := PublicKeyLength
			if ns.cs.HasKey() {
				klen = PublicKeyLength + MacBytes
			}
			if offset+klen > len(message) {
				return nil, errors.New("insufficient bytes for static key")
			}
			var err error
			ns.rs, err = ns.decryptAndHash(message[offset : offset+klen])
			if err != nil {
				return nil, err
			}
			offset += klen

		case TokenEE, TokenES, TokenSE, TokenSS:
			useStatic := getKeyPattern(token, ns.initiator)
			localKey := ns.s
			if !useStatic.local {
				localKey = ns.e
			}
			remoteKey := ns.rs
			if !useStatic.remote {
				remoteKey = ns.re
			}
			if err := ns.mixKey(remoteKey, localKey); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unexpected token: %d", token)
		}
	}

	// Decrypt payload
	payload, err := ns.decryptAndHash(message[offset:])
	if err != nil {
		return nil, err
	}

	// Finalize if handshake complete
	if len(ns.handshakeQueue) == 0 {
		if err := ns.final(); err != nil {
			return nil, err
		}
	}

	return payload, nil
}

// final completes the handshake and derives transport keys.
func (ns *NoiseState) final() error {
	ns.hash = ns.handshakeHash()

	keys, err := ns.split()
	if err != nil {
		return err
	}

	if ns.initiator {
		ns.tx = keys[0]
		ns.rx = keys[1]
	} else {
		ns.tx = keys[1]
		ns.rx = keys[0]
	}

	ns.complete = true

	// Clear handshake state
	ns.clearHandshake()

	return nil
}

// clearHandshake clears sensitive handshake data.
func (ns *NoiseState) clearHandshake() {
	if ns.e != nil {
		for i := range ns.e.SecretKey {
			ns.e.SecretKey[i] = 0
		}
		for i := range ns.e.PublicKey {
			ns.e.PublicKey[i] = 0
		}
		ns.e = nil
	}
	if ns.re != nil {
		for i := range ns.re {
			ns.re[i] = 0
		}
		ns.re = nil
	}
	// Zero static private key
	if ns.s != nil {
		for i := range ns.s.SecretKey {
			ns.s.SecretKey[i] = 0
		}
	}
	// Zero PSK
	if ns.psk != nil {
		for i := range ns.psk {
			ns.psk[i] = 0
		}
		ns.psk = nil
	}
}

// IsComplete returns true if handshake is complete.
func (ns *NoiseState) IsComplete() bool {
	return ns.complete
}

// Hash returns the handshake hash (only valid after completion).
func (ns *NoiseState) Hash() []byte {
	if ns.hash != nil {
		result := make([]byte, len(ns.hash))
		copy(result, ns.hash)
		return result
	}
	return nil
}

// Tx returns the transmit cipher state (only valid after completion).
func (ns *NoiseState) Tx() *CipherState {
	return ns.tx
}

// Rx returns the receive cipher state (only valid after completion).
func (ns *NoiseState) Rx() *CipherState {
	return ns.rx
}

// StaticPublicKey returns the local static public key.
func (ns *NoiseState) StaticPublicKey() []byte {
	if ns.s != nil {
		key := make([]byte, len(ns.s.PublicKey))
		copy(key, ns.s.PublicKey)
		return key
	}
	return nil
}

// RemoteStaticPublicKey returns a copy of the remote static public key (rs).
func (ns *NoiseState) RemoteStaticPublicKey() []byte {
	if ns.rs == nil {
		return nil
	}
	key := make([]byte, len(ns.rs))
	copy(key, ns.rs)
	return key
}

// keyPatternResult holds which keys to use.
type keyPatternResult struct {
	local  bool
	remote bool
}

// getKeyPattern determines which keys to use based on token and role.
func getKeyPattern(token Token, initiator bool) (result keyPatternResult) {
	switch token {
	case TokenEE:
		// Both ephemeral
		result.local = false
		result.remote = false

	case TokenES:
		// Initiator: ephemeral local, static remote
		// Responder: static local, ephemeral remote
		result.local = !initiator
		result.remote = initiator

	case TokenSE:
		// Initiator: static local, ephemeral remote
		// Responder: ephemeral local, static remote
		result.local = initiator
		result.remote = !initiator

	case TokenSS:
		// Both static
		result.local = true
		result.remote = true
	}

	return result
}

// hasPskToken checks if handshake pattern contains PSK token.
func hasPskToken(handshake [][]Token) bool {
	for _, msg := range handshake {
		if slices.Contains(msg, TokenPSK) {
			return true
		}
	}
	return false
}
