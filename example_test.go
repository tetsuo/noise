package noise_test

import (
	"fmt"
	"log"

	"github.com/tetsuo/noise"
)

// Example demonstrates a basic XX handshake pattern.
func Example() {
	// Create initiator and responder
	initiator, err := noise.NewNoiseState(
		noise.PatternXX,
		true,
		&noise.Config{},
	)
	if err != nil {
		log.Fatal(err)
	}

	responder, err := noise.NewNoiseState(
		noise.PatternXX,
		false,
		&noise.Config{},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize with prologue
	prologue := []byte("MyProtocol v1.0")
	initiator.Initialize(prologue, nil)
	responder.Initialize(prologue, nil)

	// Perform handshake
	// Message 1: initiator -> responder
	msg1, _ := initiator.Send([]byte("Hello"))
	payload1, _ := responder.Recv(msg1)
	fmt.Printf("Responder received: %s\n", payload1)

	// Message 2: responder -> initiator
	msg2, _ := responder.Send([]byte("World"))
	payload2, _ := initiator.Recv(msg2)
	fmt.Printf("Initiator received: %s\n", payload2)

	// Message 3: initiator -> responder (finalizes)
	msg3, _ := initiator.Send(nil)
	responder.Recv(msg3)

	// Handshake complete
	if initiator.IsComplete() && responder.IsComplete() {
		fmt.Println("Handshake complete!")

		// Use transport keys for encrypted communication
		plaintext := []byte("Secret")
		ciphertext, _ := initiator.Tx().Encrypt(nil, plaintext, nil)
		decrypted, _ := responder.Rx().Decrypt(nil, ciphertext, nil)
		fmt.Printf("Transport message: %s\n", decrypted)
	}

	// Output:
	// Responder received: Hello
	// Initiator received: World
	// Handshake complete!
	// Transport message: Secret
}

// ExamplePSK demonstrates PSK handshake.
func Example_psk() {
	psk := []byte("my-32-byte-pre-shared-key-here!!")

	initiator, _ := noise.NewNoiseState(
		noise.PatternXXpsk0,
		true,
		&noise.Config{PSK: psk},
	)

	responder, _ := noise.NewNoiseState(
		noise.PatternXXpsk0,
		false,
		&noise.Config{PSK: psk},
	)

	prologue := []byte("PSK Demo")
	initiator.Initialize(prologue, nil)
	responder.Initialize(prologue, nil)

	// Complete handshake
	msg1, _ := initiator.Send(nil)
	responder.Recv(msg1)
	msg2, _ := responder.Send(nil)
	initiator.Recv(msg2)
	msg3, _ := initiator.Send(nil)
	responder.Recv(msg3)

	fmt.Printf("PSK handshake complete: %v\n", initiator.IsComplete())

	// Output:
	// PSK handshake complete: true
}

// Example_ik demonstrates IK pattern with pre-known responder key.
func Example_ik() {
	// Responder has a known static key
	responder, _ := noise.NewNoiseState(
		noise.PatternIK,
		false,
		&noise.Config{},
	)
	responderPublicKey := responder.StaticPublicKey()

	// Initiator knows responder's key in advance
	initiator, _ := noise.NewNoiseState(
		noise.PatternIK,
		true,
		&noise.Config{},
	)

	prologue := []byte("IK Demo")
	initiator.Initialize(prologue, responderPublicKey)
	responder.Initialize(prologue, nil)

	// Complete 2-message handshake
	msg1, _ := initiator.Send(nil)
	responder.Recv(msg1)
	msg2, _ := responder.Send(nil)
	initiator.Recv(msg2)

	fmt.Printf("IK handshake complete: %v\n", initiator.IsComplete())

	// Output:
	// IK handshake complete: true
}

// Example_customKeys demonstrates using custom static keypairs.
func Example_customKeys() {
	curve := noise.DefaultCurve

	// Generate static keypairs
	initiatorStatic, _ := curve.GenerateKeyPair(nil)
	responderStatic, _ := curve.GenerateKeyPair(nil)

	// Create states with custom keys
	initiator, _ := noise.NewNoiseState(
		noise.PatternXX,
		true,
		&noise.Config{StaticKeypair: initiatorStatic},
	)

	responder, _ := noise.NewNoiseState(
		noise.PatternXX,
		false,
		&noise.Config{StaticKeypair: responderStatic},
	)

	prologue := []byte{}
	initiator.Initialize(prologue, nil)
	responder.Initialize(prologue, nil)

	// Complete handshake
	msg1, _ := initiator.Send(nil)
	responder.Recv(msg1)
	msg2, _ := responder.Send(nil)
	initiator.Recv(msg2)
	msg3, _ := initiator.Send(nil)
	responder.Recv(msg3)

	fmt.Printf("Custom keys handshake: %v\n", initiator.IsComplete())

	// Output:
	// Custom keys handshake: true
}
