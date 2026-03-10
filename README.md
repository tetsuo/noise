# noisehandshake

A pure Go implementation of the core [Noise Protocol](https://noiseprotocol.org/) handshake patterns.

**Supported patterns**:

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

    nhs "github.com/tetsuo/noisehandshake"
)

func main() {
    // Create initiator and responder
    initiator, err := nhs.NewNoiseState(
        nhs.PatternXX,
        true, // initiator role
        &nhs.Config{},
    )
    if err != nil {
        log.Fatal(err)
    }

    responder, err := nhs.NewNoiseState(
        nhs.PatternXX,
        false, // responder role
        &nhs.Config{},
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

        // Get handshake hash (can be used for channel binding)
        hash := initiator.GetHash()
        fmt.Printf("Handshake hash: %x\n", hash)

        // Get transport cipher states
        txInit := initiator.GetTX()
        rxInit := initiator.GetRX()
        txResp := responder.GetTX()
        rxResp := responder.GetRX()

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

initiator, _ := nhs.NewNoiseState(
    nhs.PatternXXpsk0,
    true,
    &nhs.Config{PSK: psk},
)

responder, _ := nhs.NewNoiseState(
    nhs.PatternXXpsk0,
    false,
    &nhs.Config{PSK: psk},
)
```

### IK pattern (pre-known responder key)

```go
// Responder's static public key is known in advance
responderStaticKey := getResponderPublicKey()

initiator, _ := nhs.NewNoiseState(
    nhs.PatternIK,
    true,
    &nhs.Config{},
)

// Initialize with remote static key
initiator.Initialize(prologue, responderStaticKey)
```

### Using custom static keys

```go
// Generate or load static keypair
curve := nhs.DefaultCurve
staticKeypair, _ := curve.GenerateKeyPair(nil)

// Or use a seed for deterministic keys
seed := make([]byte, 32)
// ... fill seed ...
staticKeypair, _ = curve.GenerateKeyPair(seed)

initiator, _ := nhs.NewNoiseState(
    nhs.PatternXX,
    true,
    &nhs.Config{StaticKeypair: staticKeypair},
)
```

## References

- [Noise Protocol Framework](https://noiseprotocol.org/)
- [Noise Protocol Specification (Revision 34)](https://noiseprotocol.org/noise.html)
- [RFC 7539: ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539)
- [RFC 7748: Curve25519](https://tools.ietf.org/html/rfc7748)
- [RFC 7693: BLAKE2](https://tools.ietf.org/html/rfc7693)
