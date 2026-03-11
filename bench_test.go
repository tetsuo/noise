package noise_test

import (
	"testing"

	"github.com/tetsuo/noise"
)

// setupTransportPair completes an NN handshake and returns tx/rx cipher states.
func setupTransportPair(b *testing.B) (tx, rx *noise.CipherState) {
	b.Helper()

	initiator, err := noise.NewNoiseState(noise.PatternNN, true, &noise.Config{})
	if err != nil {
		b.Fatal(err)
	}
	responder, err := noise.NewNoiseState(noise.PatternNN, false, &noise.Config{})
	if err != nil {
		b.Fatal(err)
	}

	if err := initiator.Initialize([]byte("bench"), nil); err != nil {
		b.Fatal(err)
	}
	if err := responder.Initialize([]byte("bench"), nil); err != nil {
		b.Fatal(err)
	}

	msg1, err := initiator.Send(nil)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := responder.Recv(msg1); err != nil {
		b.Fatal(err)
	}
	msg2, err := responder.Send(nil)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := initiator.Recv(msg2); err != nil {
		b.Fatal(err)
	}

	return initiator.Tx(), responder.Rx()
}

func BenchmarkEncrypt64(b *testing.B) {
	tx, _ := setupTransportPair(b)
	plaintext := make([]byte, 64)
	buf := make([]byte, 0, 64+16)
	b.SetBytes(64)
	b.ReportAllocs()

	for b.Loop() {
		_, err := tx.Encrypt(buf[:0], plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt64(b *testing.B) {
	benchDecrypt(b, 64)
}

func benchDecrypt(b *testing.B, size int) {
	b.Helper()
	tx, rx := setupTransportPair(b)
	plaintext := make([]byte, size)

	// Pre-encrypt exactly b.N messages to avoid measuring encryption time
	ciphertexts := make([][]byte, b.N)
	for i := range b.N {
		ct, err := tx.Encrypt(nil, plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
		ciphertexts[i] = ct
	}

	buf := make([]byte, 0, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := rx.Decrypt(buf[:0], ciphertexts[i], nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt1024(b *testing.B) {
	tx, _ := setupTransportPair(b)
	plaintext := make([]byte, 1024)
	buf := make([]byte, 0, 1024+16)
	b.SetBytes(1024)
	b.ReportAllocs()

	for b.Loop() {
		_, err := tx.Encrypt(buf[:0], plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt1024(b *testing.B) {
	benchDecrypt(b, 1024)
}
