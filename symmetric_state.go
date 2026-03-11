package noisehandshake

// symmetricState extends CipherState with hashing and key derivation.
type symmetricState struct {
	cs          CipherState
	curve       *Curve
	digest      []byte
	chainingKey []byte
}

// newSymmetricState creates a new symmetric state.
func newSymmetricState(curve *Curve) *symmetricState {
	if curve == nil {
		curve = DefaultCurve
	}
	return &symmetricState{
		curve:       curve,
		digest:      make([]byte, hashLen),
		chainingKey: make([]byte, hashLen),
	}
}

// initializeSymmetric initializes the symmetric state with protocol name.
func (ss *symmetricState) initializeSymmetric(protocolName []byte) {
	if len(protocolName) <= hashLen {
		copy(ss.chainingKey, protocolName)
		copy(ss.digest, protocolName)
		for i := len(protocolName); i < hashLen; i++ {
			ss.chainingKey[i] = 0
			ss.digest[i] = 0
		}
	} else {
		h := newBLAKE2b512()
		h.Write(protocolName)
		hashed := h.Sum(nil)
		copy(ss.chainingKey, hashed)
		copy(ss.digest, hashed)
	}
}

// mixHash mixes data into the digest.
func (ss *symmetricState) mixHash(data []byte) {
	h := newBLAKE2b512()
	h.Write(ss.digest)
	h.Write(data)
	ss.digest = h.Sum(ss.digest[:0])
}

// mixKeyAndHash mixes a key into both the chaining key and digest.
func (ss *symmetricState) mixKeyAndHash(key []byte) {
	outputs := hkdf(ss.chainingKey, key, nil, 3)

	ss.chainingKey = outputs[0]
	ss.mixHash(outputs[1])
	ss.cs.initializeKey(outputs[2][:32])
}

// mixKeyNormal mixes a key into the chaining key.
func (ss *symmetricState) mixKeyNormal(key []byte) {
	outputs := hkdf(ss.chainingKey, key, nil, 2)

	ss.chainingKey = outputs[0]
	ss.cs.initializeKey(outputs[1][:32])
}

// mixKey performs DH and mixes the result into the chaining key.
func (ss *symmetricState) mixKey(remoteKey []byte, localKey *KeyPair) error {
	dh, err := ss.curve.DH(remoteKey, localKey)
	if err != nil {
		return err
	}

	outputs := hkdf(ss.chainingKey, dh, nil, 2)

	ss.chainingKey = outputs[0]
	ss.cs.initializeKey(outputs[1][:32])
	return nil
}

// encryptAndHash encrypts plaintext and mixes ciphertext into digest.
func (ss *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := ss.cs.Encrypt(nil, plaintext, ss.digest)
	if err != nil {
		return nil, err
	}
	ss.mixHash(ciphertext)
	return ciphertext, nil
}

// decryptAndHash decrypts ciphertext and mixes it into digest.
func (ss *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := ss.cs.Decrypt(nil, ciphertext, ss.digest)
	if err != nil {
		return nil, err
	}
	ss.mixHash(ciphertext)
	return plaintext, nil
}

// handshakeHash returns the current handshake hash.
func (ss *symmetricState) handshakeHash() []byte {
	hash := make([]byte, hashLen)
	copy(hash, ss.digest)
	return hash
}

// split derives two cipher states from the current state.
// Clears the symmetric state for forward secrecy.
func (ss *symmetricState) split() ([]*CipherState, error) {
	outputs := hkdf(ss.chainingKey, []byte{}, nil, 2)

	k1, err := newCipherState(outputs[0][:32])
	if err != nil {
		return nil, err
	}
	k2, err := newCipherState(outputs[1][:32])
	if err != nil {
		return nil, err
	}

	ss.clear()

	return []*CipherState{k1, k2}, nil
}

// clear clears sensitive data.
func (ss *symmetricState) clear() {
	ss.cs.Clear()

	if ss.digest != nil {
		for i := range ss.digest {
			ss.digest[i] = 0
		}
	}
	if ss.chainingKey != nil {
		for i := range ss.chainingKey {
			ss.chainingKey[i] = 0
		}
	}

	ss.digest = nil
	ss.chainingKey = nil
	ss.curve = nil
}
