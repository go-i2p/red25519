package red25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(pub) != PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pub), PublicKeySize)
	}
	if len(priv) != PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(priv), PrivateKeySize)
	}
	// Public key embedded in private key must match returned public key.
	if !pub.Equal(priv.Public()) {
		t.Error("public key mismatch: returned pub != priv.Public()")
	}
}

func TestGenerateKeyRandError(t *testing.T) {
	// An io.Reader that always fails.
	failReader := &errReader{err: errors.New("entropy failure")}
	_, _, err := GenerateKey(failReader)
	if err == nil {
		t.Fatal("expected error from failing reader, got nil")
	}
}

type errReader struct{ err error }

func (r *errReader) Read([]byte) (int, error) { return 0, r.err }

func TestNewKeyFromSeed(t *testing.T) {
	seed := make([]byte, SeedSize)
	_, _ = io.ReadFull(rand.Reader, seed)

	priv1 := NewKeyFromSeed(seed)
	priv2 := NewKeyFromSeed(seed)

	// Deterministic: same seed must produce same key.
	if !priv1.Equal(priv2) {
		t.Error("NewKeyFromSeed is not deterministic")
	}
}

func TestNewKeyFromSeedMatchesStdlib(t *testing.T) {
	seed := make([]byte, SeedSize)
	_, _ = io.ReadFull(rand.Reader, seed)

	redPriv := NewKeyFromSeed(seed)
	stdPriv := ed25519.NewKeyFromSeed(seed)

	// Public keys should match.
	if !bytes.Equal([]byte(redPriv.Public()), stdPriv.Public().(ed25519.PublicKey)) {
		t.Error("public key does not match crypto/ed25519")
	}
}

func TestNewKeyFromSeedPanicsBadLength(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for bad seed length")
		}
	}()
	NewKeyFromSeed(make([]byte, 16))
}

func TestPrivateKeySeed(t *testing.T) {
	seed := make([]byte, SeedSize)
	_, _ = io.ReadFull(rand.Reader, seed)

	priv := NewKeyFromSeed(seed)
	got := priv.Seed()
	if !bytes.Equal(got, seed) {
		t.Error("Seed() does not return original seed")
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("hello, red25519")
	sig := Sign(priv, msg)

	if len(sig) != SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), SignatureSize)
	}
	if !Verify(pub, msg, sig) {
		t.Error("valid signature failed verification")
	}
}

func TestSignVerifyDeterministic(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	msg := []byte("deterministic nonce")

	sig1 := Sign(priv, msg)
	sig2 := Sign(priv, msg)
	if !bytes.Equal(sig1, sig2) {
		t.Error("signing is not deterministic")
	}
}

func TestVerifyTamperedMessage(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	msg := []byte("original message")
	sig := Sign(priv, msg)

	tampered := []byte("tampered message")
	if Verify(pub, tampered, sig) {
		t.Error("verification should fail for tampered message")
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	msg := []byte("test message")
	sig := Sign(priv, msg)

	// Flip a bit in the signature.
	sig[0] ^= 0x01
	if Verify(pub, msg, sig) {
		t.Error("verification should fail for tampered signature")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	pub2, _, _ := GenerateKey(rand.Reader)

	msg := []byte("wrong key test")
	sig := Sign(priv, msg)

	if Verify(pub2, msg, sig) {
		t.Error("verification should fail with wrong public key")
	}
}

func TestVerifyBadInputLengths(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	msg := []byte("test")
	sig := Sign(priv, msg)

	// Short public key.
	if Verify(pub[:16], msg, sig) {
		t.Error("should reject short public key")
	}
	// Short signature.
	if Verify(pub, msg, sig[:32]) {
		t.Error("should reject short signature")
	}
	// Empty public key.
	if Verify(PublicKey{}, msg, sig) {
		t.Error("should reject empty public key")
	}
	// Empty signature.
	if Verify(pub, msg, []byte{}) {
		t.Error("should reject empty signature")
	}
}

func TestSignPanicsBadKeyLength(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for bad private key length")
		}
	}()
	Sign(PrivateKey(make([]byte, 32)), []byte("msg"))
}

func TestCompatibilitySignWithStdlib(t *testing.T) {
	// Our unblinded signatures should be verifiable by crypto/ed25519.
	seed := make([]byte, SeedSize)
	_, _ = io.ReadFull(rand.Reader, seed)

	redPriv := NewKeyFromSeed(seed)
	stdPriv := ed25519.NewKeyFromSeed(seed)

	msg := []byte("cross-library compatibility")

	redSig := Sign(redPriv, msg)
	stdSig := ed25519.Sign(stdPriv, msg)

	// Signatures should be identical (same deterministic nonce derivation).
	if !bytes.Equal(redSig, stdSig) {
		t.Error("red25519 signature differs from crypto/ed25519 signature")
	}

	// Cross-verify: our sig verified by stdlib.
	stdPub := stdPriv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(stdPub, msg, redSig) {
		t.Error("crypto/ed25519 failed to verify red25519 signature")
	}

	// Cross-verify: stdlib sig verified by us.
	if !Verify(redPriv.Public(), msg, stdSig) {
		t.Error("red25519 failed to verify crypto/ed25519 signature")
	}
}

func TestSignVerifyEmptyMessage(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	sig := Sign(priv, []byte{})
	if !Verify(pub, []byte{}, sig) {
		t.Error("failed to verify signature on empty message")
	}
}

func TestSignVerifyLargeMessage(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	msg := make([]byte, 1<<16) // 64 KiB
	_, _ = io.ReadFull(rand.Reader, msg)

	sig := Sign(priv, msg)
	if !Verify(pub, msg, sig) {
		t.Error("failed to verify signature on large message")
	}
}

func TestPublicKeyEqual(t *testing.T) {
	pub1, _, _ := GenerateKey(rand.Reader)
	pub2, _, _ := GenerateKey(rand.Reader)

	if !pub1.Equal(pub1) {
		t.Error("public key should equal itself")
	}
	if pub1.Equal(pub2) {
		t.Error("different public keys should not be equal")
	}
	if pub1.Equal(PublicKey{}) {
		t.Error("should not equal empty key")
	}
}

func TestPrivateKeyEqual(t *testing.T) {
	_, priv1, _ := GenerateKey(rand.Reader)
	_, priv2, _ := GenerateKey(rand.Reader)

	if !priv1.Equal(priv1) {
		t.Error("private key should equal itself")
	}
	if priv1.Equal(priv2) {
		t.Error("different private keys should not be equal")
	}
}

// TestEdgeCases covers edge-case inputs: nil messages and identity-point
// public key behavior.
func TestEdgeCases(t *testing.T) {
	t.Run("nil message sign/verify", func(t *testing.T) {
		pub, priv, _ := GenerateKey(rand.Reader)
		sig := Sign(priv, nil)
		if !Verify(pub, nil, sig) {
			t.Error("should verify signature on nil message")
		}
		// nil and empty should produce the same signature.
		sigEmpty := Sign(priv, []byte{})
		if !bytes.Equal(sig, sigEmpty) {
			t.Error("nil and empty message should produce identical signatures")
		}
	})

	t.Run("identity point public key", func(t *testing.T) {
		// The identity point (all zeros in compressed form) is a degenerate
		// public key. Signatures with it should still "verify" algebraically
		// but callers should avoid this key in practice.
		identity := make(PublicKey, PublicKeySize)
		identity[0] = 0x01 // compressed identity point encoding in Ed25519
		_, priv, _ := GenerateKey(rand.Reader)
		msg := []byte("test")
		sig := Sign(priv, msg)
		// Verification with a random sig against identity should fail
		// because the key/sig don't correspond.
		if Verify(identity, msg, sig) {
			t.Error("signature should not verify against unrelated identity-like key")
		}
	})

	t.Run("invalid point encoding in public key", func(t *testing.T) {
		// All-0xFF is not a valid point encoding.
		badPub := make(PublicKey, PublicKeySize)
		for i := range badPub {
			badPub[i] = 0xFF
		}
		if Verify(badPub, []byte("test"), make([]byte, SignatureSize)) {
			t.Error("should reject invalid point encoding")
		}
	})

	t.Run("non-canonical S in signature", func(t *testing.T) {
		pub, priv, _ := GenerateKey(rand.Reader)
		msg := []byte("canonical test")
		sig := Sign(priv, msg)

		// Set S to a value >= l (the group order) by setting all bits.
		for i := 32; i < 64; i++ {
			sig[i] = 0xFF
		}
		if Verify(pub, msg, sig) {
			t.Error("should reject non-canonical S >= l")
		}
	})
}
