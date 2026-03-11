package noisehandshake_test

import (
	"bytes"
	"testing"

	nhs "github.com/tetsuo/noisehandshake"
)

func TestBasicHandshakeXX(t *testing.T) {
	// Create initiator
	initiatorConfig := &nhs.Config{}
	initiator, err := nhs.NewNoiseState(nhs.PatternXX, true, initiatorConfig)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	// Create responder
	responderConfig := &nhs.Config{}
	responder, err := nhs.NewNoiseState(nhs.PatternXX, false, responderConfig)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	prologue := []byte("MyProtocol")

	// Initialize both sides
	if err := initiator.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize initiator: %v", err)
	}
	if err := responder.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize responder: %v", err)
	}

	// Message 1: initiator -> responder
	msg1, err := initiator.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 1: %v", err)
	}

	payload1, err := responder.Recv(msg1)
	if err != nil {
		t.Fatalf("Failed to receive message 1: %v", err)
	}
	if len(payload1) != 0 {
		t.Errorf("Expected empty payload, got %d bytes", len(payload1))
	}

	// Message 2: responder -> initiator
	msg2, err := responder.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 2: %v", err)
	}

	payload2, err := initiator.Recv(msg2)
	if err != nil {
		t.Fatalf("Failed to receive message 2: %v", err)
	}
	if len(payload2) != 0 {
		t.Errorf("Expected empty payload, got %d bytes", len(payload2))
	}

	// Message 3: initiator -> responder
	msg3, err := initiator.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 3: %v", err)
	}

	payload3, err := responder.Recv(msg3)
	if err != nil {
		t.Fatalf("Failed to receive message 3: %v", err)
	}
	if len(payload3) != 0 {
		t.Errorf("Expected empty payload, got %d bytes", len(payload3))
	}

	// Verify handshake is complete
	if !initiator.IsComplete() {
		t.Error("Initiator handshake not complete")
	}
	if !responder.IsComplete() {
		t.Error("Responder handshake not complete")
	}

	// Verify handshake hashes match and are non-zero
	initHash := initiator.Hash()
	respHash := responder.Hash()
	if !bytes.Equal(initHash, respHash) {
		t.Error("Handshake hashes do not match")
	}
	allZero := true
	for _, b := range initHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Handshake hash is all zeros")
	}
}

func TestHandshakeWithPayloadXX(t *testing.T) {
	// Create initiator and responder
	initiator, err := nhs.NewNoiseState(nhs.PatternXX, true, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := nhs.NewNoiseState(nhs.PatternXX, false, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	prologue := []byte("TestProtocol")

	if err := initiator.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize initiator: %v", err)
	}
	if err := responder.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize responder: %v", err)
	}

	// Message 1 with payload
	payload1 := []byte("Hello from initiator")
	msg1, err := initiator.Send(payload1)
	if err != nil {
		t.Fatalf("Failed to send message 1: %v", err)
	}

	recvPayload1, err := responder.Recv(msg1)
	if err != nil {
		t.Fatalf("Failed to receive message 1: %v", err)
	}
	if !bytes.Equal(payload1, recvPayload1) {
		t.Errorf("Payload mismatch: expected %s, got %s", payload1, recvPayload1)
	}

	// Message 2 with payload
	payload2 := []byte("Hello from responder")
	msg2, err := responder.Send(payload2)
	if err != nil {
		t.Fatalf("Failed to send message 2: %v", err)
	}

	recvPayload2, err := initiator.Recv(msg2)
	if err != nil {
		t.Fatalf("Failed to receive message 2: %v", err)
	}
	if !bytes.Equal(payload2, recvPayload2) {
		t.Errorf("Payload mismatch: expected %s, got %s", payload2, recvPayload2)
	}

	// Message 3
	msg3, err := initiator.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 3: %v", err)
	}

	_, err = responder.Recv(msg3)
	if err != nil {
		t.Fatalf("Failed to receive message 3: %v", err)
	}

	if !initiator.IsComplete() || !responder.IsComplete() {
		t.Error("Handshake not complete")
	}
}

func TestTransportMessagesXX(t *testing.T) {
	// Complete a handshake
	initiator, err := nhs.NewNoiseState(nhs.PatternXX, true, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := nhs.NewNoiseState(nhs.PatternXX, false, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	prologue := []byte{}
	if err := initiator.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize initiator: %v", err)
	}
	if err := responder.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize responder: %v", err)
	}

	// Complete handshake
	msg1, _ := initiator.Send(nil)
	responder.Recv(msg1)
	msg2, _ := responder.Send(nil)
	initiator.Recv(msg2)
	msg3, _ := initiator.Send(nil)
	responder.Recv(msg3)

	// Test transport messages
	plaintext := []byte("Secret message")

	// Initiator sends to responder
	ciphertext, err := initiator.Tx().Encrypt(nil, plaintext, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := responder.Rx().Decrypt(nil, ciphertext, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Transport message mismatch: expected %s, got %s", plaintext, decrypted)
	}

	// Responder sends to initiator
	plaintext2 := []byte("Secret reply")
	ciphertext2, err := responder.Tx().Encrypt(nil, plaintext2, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt reply: %v", err)
	}

	decrypted2, err := initiator.Rx().Decrypt(nil, ciphertext2, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt reply: %v", err)
	}

	if !bytes.Equal(plaintext2, decrypted2) {
		t.Errorf("Transport reply mismatch: expected %s, got %s", plaintext2, decrypted2)
	}
}

func TestNNPattern(t *testing.T) {
	initiator, err := nhs.NewNoiseState(nhs.PatternNN, true, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := nhs.NewNoiseState(nhs.PatternNN, false, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	prologue := []byte("NN_Test")
	if err := initiator.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize initiator: %v", err)
	}
	if err := responder.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize responder: %v", err)
	}

	// Message 1
	msg1, err := initiator.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 1: %v", err)
	}

	_, err = responder.Recv(msg1)
	if err != nil {
		t.Fatalf("Failed to receive message 1: %v", err)
	}

	// Message 2
	msg2, err := responder.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 2: %v", err)
	}

	_, err = initiator.Recv(msg2)
	if err != nil {
		t.Fatalf("Failed to receive message 2: %v", err)
	}

	if !initiator.IsComplete() || !responder.IsComplete() {
		t.Error("NN handshake not complete")
	}
}

func TestPSKHandshakeXXpsk0(t *testing.T) {
	psk := []byte("my-shared-secret-key-32-bytes!!!")

	initiator, err := nhs.NewNoiseState(nhs.PatternXXpsk0, true, &nhs.Config{PSK: psk})
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := nhs.NewNoiseState(nhs.PatternXXpsk0, false, &nhs.Config{PSK: psk})
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	prologue := []byte("PSK_Test")
	if err := initiator.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize initiator: %v", err)
	}
	if err := responder.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize responder: %v", err)
	}

	// Complete handshake
	msg1, _ := initiator.Send(nil)
	responder.Recv(msg1)
	msg2, _ := responder.Send(nil)
	initiator.Recv(msg2)
	msg3, _ := initiator.Send(nil)
	responder.Recv(msg3)

	if !initiator.IsComplete() || !responder.IsComplete() {
		t.Error("PSK handshake not complete")
	}

	// Verify hashes match and are non-zero
	if !bytes.Equal(initiator.Hash(), responder.Hash()) {
		t.Error("PSK handshake hashes do not match")
	}
	hash := initiator.Hash()
	allZero := true
	for _, b := range hash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("PSK handshake hash is all zeros")
	}
}

func TestIKPattern(t *testing.T) {
	// Responder generates static key in advance
	responder, err := nhs.NewNoiseState(nhs.PatternIK, false, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}
	responderStaticPub := responder.StaticPublicKey()

	// Initiator knows responder's static public key
	initiator, err := nhs.NewNoiseState(nhs.PatternIK, true, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	prologue := []byte("IK_Test")
	if err := initiator.Initialize(prologue, responderStaticPub); err != nil {
		t.Fatalf("Failed to initialize initiator: %v", err)
	}
	if err := responder.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize responder: %v", err)
	}

	// Complete handshake
	msg1, err := initiator.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 1: %v", err)
	}

	_, err = responder.Recv(msg1)
	if err != nil {
		t.Fatalf("Failed to receive message 1: %v", err)
	}

	msg2, err := responder.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 2: %v", err)
	}

	_, err = initiator.Recv(msg2)
	if err != nil {
		t.Fatalf("Failed to receive message 2: %v", err)
	}

	if !initiator.IsComplete() || !responder.IsComplete() {
		t.Error("IK handshake not complete")
	}
}

func TestXKPattern(t *testing.T) {
	// Responder has a known static key; initiator knows it in advance
	responder, err := nhs.NewNoiseState(nhs.PatternXK, false, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}
	responderStaticPub := responder.StaticPublicKey()

	initiator, err := nhs.NewNoiseState(nhs.PatternXK, true, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	prologue := []byte("XK_Test")
	if err := initiator.Initialize(prologue, responderStaticPub); err != nil {
		t.Fatalf("Failed to initialize initiator: %v", err)
	}
	if err := responder.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize responder: %v", err)
	}

	// 3-message XK handshake
	msg1, err := initiator.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 1: %v", err)
	}
	if _, err = responder.Recv(msg1); err != nil {
		t.Fatalf("Failed to receive message 1: %v", err)
	}

	msg2, err := responder.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 2: %v", err)
	}
	if _, err = initiator.Recv(msg2); err != nil {
		t.Fatalf("Failed to receive message 2: %v", err)
	}

	msg3, err := initiator.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 3: %v", err)
	}
	if _, err = responder.Recv(msg3); err != nil {
		t.Fatalf("Failed to receive message 3: %v", err)
	}

	if !initiator.IsComplete() || !responder.IsComplete() {
		t.Error("XK handshake not complete")
	}

	// Both sides should arrive at the same hash
	if !bytes.Equal(initiator.Hash(), responder.Hash()) {
		t.Error("XK handshake hashes do not match")
	}

	// Transport: initiator -> responder and back
	plain := []byte("XK transport test")
	ct, err := initiator.Tx().Encrypt(nil, plain, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	got, err := responder.Rx().Decrypt(nil, ct, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if !bytes.Equal(plain, got) {
		t.Errorf("XK transport mismatch: got %s", got)
	}
}

func TestNNpsk0Pattern(t *testing.T) {
	psk := []byte("nNpsk0-shared-secret-32-bytes!!!")

	initiator, err := nhs.NewNoiseState(nhs.PatternNNpsk0, true, &nhs.Config{PSK: psk})
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}
	responder, err := nhs.NewNoiseState(nhs.PatternNNpsk0, false, &nhs.Config{PSK: psk})
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	prologue := []byte("NNpsk0_Test")
	if err := initiator.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize initiator: %v", err)
	}
	if err := responder.Initialize(prologue, nil); err != nil {
		t.Fatalf("Failed to initialize responder: %v", err)
	}

	msg1, err := initiator.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 1: %v", err)
	}
	if _, err = responder.Recv(msg1); err != nil {
		t.Fatalf("Failed to receive message 1: %v", err)
	}

	msg2, err := responder.Send(nil)
	if err != nil {
		t.Fatalf("Failed to send message 2: %v", err)
	}
	if _, err = initiator.Recv(msg2); err != nil {
		t.Fatalf("Failed to receive message 2: %v", err)
	}

	if !initiator.IsComplete() || !responder.IsComplete() {
		t.Error("NNpsk0 handshake not complete")
	}
	if !bytes.Equal(initiator.Hash(), responder.Hash()) {
		t.Error("NNpsk0 handshake hashes do not match")
	}
}

func TestRemoteStaticPublicKey(t *testing.T) {
	// After an XX handshake, each side should know the other's static public key
	initiator, err := nhs.NewNoiseState(nhs.PatternXX, true, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}
	responder, err := nhs.NewNoiseState(nhs.PatternXX, false, &nhs.Config{})
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	initStaticPub := initiator.StaticPublicKey()
	respStaticPub := responder.StaticPublicKey()

	prologue := []byte("remote-static-test")
	initiator.Initialize(prologue, nil)
	responder.Initialize(prologue, nil)

	msg1, _ := initiator.Send(nil)
	responder.Recv(msg1)
	msg2, _ := responder.Send(nil)
	initiator.Recv(msg2)
	msg3, _ := initiator.Send(nil)
	responder.Recv(msg3)

	// Initiator should have learned responder's static key
	if !bytes.Equal(initiator.RemoteStaticPublicKey(), respStaticPub) {
		t.Error("Initiator has wrong remote static public key")
	}
	// Responder should have learned initiator's static key
	if !bytes.Equal(responder.RemoteStaticPublicKey(), initStaticPub) {
		t.Error("Responder has wrong remote static public key")
	}
}

func TestSendAfterComplete(t *testing.T) {
	initiator, _ := nhs.NewNoiseState(nhs.PatternNN, true, &nhs.Config{})
	responder, _ := nhs.NewNoiseState(nhs.PatternNN, false, &nhs.Config{})
	initiator.Initialize(nil, nil)
	responder.Initialize(nil, nil)

	msg1, _ := initiator.Send(nil)
	responder.Recv(msg1)
	msg2, _ := responder.Send(nil)
	initiator.Recv(msg2)

	// Both complete; further Send/Recv must return an error
	if _, err := initiator.Send(nil); err == nil {
		t.Error("Expected error sending after handshake complete")
	}
	if _, err := responder.Recv([]byte("junk")); err == nil {
		t.Error("Expected error receiving after handshake complete")
	}
}

func TestPSKInvalidLength(t *testing.T) {
	_, err := nhs.NewNoiseState(nhs.PatternXXpsk0, true, &nhs.Config{PSK: []byte("short")})
	if err == nil {
		t.Error("Expected error for PSK shorter than 32 bytes")
	}

	longPSK := make([]byte, 33)
	_, err = nhs.NewNoiseState(nhs.PatternXXpsk0, true, &nhs.Config{PSK: longPSK})
	if err == nil {
		t.Error("Expected error for PSK longer than 32 bytes")
	}
}
