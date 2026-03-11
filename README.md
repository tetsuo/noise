# noise

[Noise Protocol Framework](https://noiseprotocol.org/) implementation in Go.

**Supported handshake patterns**:

- **NN**: Basic ephemeral key exchange (no authentication)
- **XX**: Full mutual authentication with ephemeral and static keys
- **IK**: Initiator knows responder's static key in advance
- **XK**: Initiator knows responder's static key, delayed authentication
- **PSK variants**: NNpsk0, XXpsk0 for pre-shared key authentication

## Usage

### Basic XX handshake

```go
package main

import (
    "fmt"
    "log"

    "github.com/tetsuo/noise"
)

func main() {
    // Create initiator and responder
    initiator, err := noise.NewNoiseState(
        noise.PatternXX,
        true, // initiator role
        &noise.Config{},
    )
    if err != nil {
        log.Fatal(err)
    }

    responder, err := noise.NewNoiseState(
        noise.PatternXX,
        false, // responder role
        &noise.Config{},
    )
    if err != nil {
        log.Fatal(err)
    }

    // Initialize with prologue (optional metadata)
    prologue := []byte("MyApplication v1.0")
    initiator.Initialize(prologue, nil)
    responder.Initialize(prologue, nil)

    // Perform handshake (3 messages for XX pattern)
    // Message 1: initiator -> responder
    msg1, _ := initiator.Send([]byte("Hello"))
    payload1, _ := responder.Recv(msg1)
    fmt.Printf("Received: %s\n", payload1)

    // Message 2: responder -> initiator
    msg2, _ := responder.Send([]byte("World"))
    payload2, _ := initiator.Recv(msg2)
    fmt.Printf("Received: %s\n", payload2)

    // Message 3: initiator -> responder (finalizes handshake)
    msg3, _ := initiator.Send(nil)
    responder.Recv(msg3)

    // Handshake complete: now use transport keys
    if initiator.IsComplete() && responder.IsComplete() {
        fmt.Println("Handshake complete!")

        // Handshake hash (can be used for channel binding)
        hash := initiator.Hash()
        fmt.Printf("Handshake hash: %x\n", hash)

        // Transport cipher states
        txInit := initiator.Tx()
        rxInit := initiator.Rx()
        txResp := responder.Tx()
        rxResp := responder.Rx()

        // Send encrypted messages
        plaintext := []byte("Secret message")
        ciphertext, _ := txInit.Encrypt(plaintext, nil)
        decrypted, _ := rxResp.Decrypt(ciphertext, nil)
        fmt.Printf("Decrypted: %s\n", decrypted)
    }
}
```

### PSK handshake

```go
// Use a pre-shared key for authentication
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
```

### IK pattern (pre-known responder key)

```go
// Responder's static public key is known in advance
responderStaticKey := getResponderPublicKey()

initiator, _ := noise.NewNoiseState(
    noise.PatternIK,
    true,
    &noise.Config{},
)

// Initialize with remote static key
initiator.Initialize(prologue, responderStaticKey)
```

### Using custom static keys

```go
// Generate or load static keypair
curve := noise.DefaultCurve
staticKeypair, _ := curve.GenerateKeyPair(nil)

// Or use a seed for deterministic keys
seed := make([]byte, 32)
// ... fill seed ...
staticKeypair, _ = curve.GenerateKeyPair(seed)

initiator, _ := noise.NewNoiseState(
    noise.PatternXX,
    true,
    &noise.Config{StaticKeypair: staticKeypair},
)
```

## References

- [Noise Protocol Framework](https://noiseprotocol.org/)
- [Noise Protocol Specification (Revision 34)](https://noiseprotocol.org/noise.html)
- [RFC 7539: ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539)
- [RFC 7748: Curve25519](https://tools.ietf.org/html/rfc7748)
- [RFC 7693: BLAKE2](https://tools.ietf.org/html/rfc7693)
