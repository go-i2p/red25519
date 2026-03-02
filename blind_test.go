package red25519

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/edwards25519"
)

func TestGenerateBlindingFactor(t *testing.T) {
	bf, err := GenerateBlindingFactor(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateBlindingFactor failed: %v", err)
	}
	if len(bf) != BlindingFactorSize {
		t.Errorf("blinding factor length = %d, want %d", len(bf), BlindingFactorSize)
	}

	// Verify clamping: low 3 bits of first byte must be clear.
	if bf[0]&0x07 != 0 {
		t.Error("low 3 bits of first byte should be cleared")
	}
	// Bit 254 (bit 6 of last byte) must be set.
	if bf[31]&0x40 == 0 {
		t.Error("bit 254 should be set")
	}
	// Bit 255 (bit 7 of last byte) must be clear.
	if bf[31]&0x80 != 0 {
		t.Error("bit 255 should be cleared")
	}
}

func TestGenerateBlindingFactorRandError(t *testing.T) {
	failReader := &errReader{err: errors.New("entropy failure")}
	_, err := GenerateBlindingFactor(failReader)
	if err == nil {
		t.Fatal("expected error from failing reader, got nil")
	}
}

func TestGenerateBlindingFactorUniqueness(t *testing.T) {
	bf1, _ := GenerateBlindingFactor(rand.Reader)
	bf2, _ := GenerateBlindingFactor(rand.Reader)
	if bytes.Equal(bf1, bf2) {
		t.Error("two independent blinding factors should differ")
	}
}

func TestBlindPublicKey(t *testing.T) {
	pub, _, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)

	blindedPub, err := BlindPublicKey(pub, bf)
	if err != nil {
		t.Fatalf("BlindPublicKey failed: %v", err)
	}
	if len(blindedPub) != PublicKeySize {
		t.Errorf("blinded public key length = %d, want %d", len(blindedPub), PublicKeySize)
	}
	// Blinded public key must differ from original.
	if pub.Equal(blindedPub) {
		t.Error("blinded public key should differ from original")
	}
}

func TestBlindPublicKeyDeterministic(t *testing.T) {
	pub, _, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)

	bp1, _ := BlindPublicKey(pub, bf)
	bp2, _ := BlindPublicKey(pub, bf)
	if !bp1.Equal(bp2) {
		t.Error("BlindPublicKey should be deterministic")
	}
}

func TestBlindPublicKeyBadInputs(t *testing.T) {
	pub, _, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)

	// Bad public key length.
	if _, err := BlindPublicKey(pub[:16], bf); err == nil {
		t.Error("should reject short public key")
	}
	// Bad blinding factor length.
	if _, err := BlindPublicKey(pub, bf[:16]); err == nil {
		t.Error("should reject short blinding factor")
	}
	// Empty public key.
	if _, err := BlindPublicKey(PublicKey{}, bf); err == nil {
		t.Error("should reject empty public key")
	}
}

func TestBlindPrivateKey(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)

	blindedPriv, err := BlindPrivateKey(priv, bf)
	if err != nil {
		t.Fatalf("BlindPrivateKey failed: %v", err)
	}
	if len(blindedPriv) != blindedPrivateKeySize {
		t.Errorf("blinded private key length = %d, want %d", len(blindedPriv), blindedPrivateKeySize)
	}
	// Blinded key should differ from original (different length alone guarantees this).
	if blindedPriv.Equal(priv) {
		t.Error("blinded private key should differ from original")
	}
}

func TestBlindPrivateKeyBadInputs(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)

	// Bad private key length.
	if _, err := BlindPrivateKey(PrivateKey(make([]byte, 32)), bf); err == nil {
		t.Error("should reject bad private key length")
	}
	// Bad blinding factor length.
	if _, err := BlindPrivateKey(priv, BlindingFactor(make([]byte, 16))); err == nil {
		t.Error("should reject bad blinding factor length")
	}
}

// TestBlindKeyInvariant verifies the core algebraic invariant:
// BlindPublicKey(priv.Public(), bf) == BlindPrivateKey(priv, bf).Public()
func TestBlindKeyInvariant(t *testing.T) {
	for i := 0; i < 10; i++ {
		_, priv, _ := GenerateKey(rand.Reader)
		bf, _ := GenerateBlindingFactor(rand.Reader)

		blindedPub, err := BlindPublicKey(priv.Public(), bf)
		if err != nil {
			t.Fatalf("BlindPublicKey failed: %v", err)
		}

		blindedPriv, err := BlindPrivateKey(priv, bf)
		if err != nil {
			t.Fatalf("BlindPrivateKey failed: %v", err)
		}

		derivedPub := blindedPriv.Public()
		if !blindedPub.Equal(derivedPub) {
			t.Errorf("invariant violated: BlindPublicKey(pub, bf) != BlindPrivateKey(priv, bf).Public()")
		}
	}
}

// TestBlindedSignVerify verifies that signing with a blinded private key
// produces signatures verifiable with the corresponding blinded public key.
func TestBlindedSignVerify(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)

	blindedPriv, _ := BlindPrivateKey(priv, bf)
	blindedPub, _ := BlindPublicKey(priv.Public(), bf)

	msg := []byte("blinded signature test")
	sig := Sign(blindedPriv, msg)

	if len(sig) != SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), SignatureSize)
	}

	// Verify with blinded public key should succeed.
	if !Verify(blindedPub, msg, sig) {
		t.Error("valid blinded signature failed verification with blinded public key")
	}

	// Verify with original public key should fail.
	if Verify(priv.Public(), msg, sig) {
		t.Error("blinded signature should not verify with original public key")
	}
}

// TestBlindedSignVerifyDeterministic verifies that blinded signing is
// deterministic (same key + same message = same signature).
func TestBlindedSignVerifyDeterministic(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)
	blindedPriv, _ := BlindPrivateKey(priv, bf)

	msg := []byte("deterministic blinded nonce")
	sig1 := Sign(blindedPriv, msg)
	sig2 := Sign(blindedPriv, msg)
	if !bytes.Equal(sig1, sig2) {
		t.Error("blinded signing is not deterministic")
	}
}

// TestBlindedSignTamperedMessage verifies that blinded signatures don't
// verify against tampered messages.
func TestBlindedSignTamperedMessage(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)
	blindedPriv, _ := BlindPrivateKey(priv, bf)
	blindedPub, _ := BlindPublicKey(priv.Public(), bf)

	msg := []byte("original blinded message")
	sig := Sign(blindedPriv, msg)

	if Verify(blindedPub, []byte("tampered blinded message"), sig) {
		t.Error("should fail for tampered message")
	}
}

// TestBlindedSignEmptyMessage verifies blinded signing works with empty messages.
func TestBlindedSignEmptyMessage(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)
	blindedPriv, _ := BlindPrivateKey(priv, bf)
	blindedPub, _ := BlindPublicKey(priv.Public(), bf)

	sig := Sign(blindedPriv, []byte{})
	if !Verify(blindedPub, []byte{}, sig) {
		t.Error("blinded signature on empty message failed verification")
	}
}

// TestMultipleBlinding verifies that blinding is composable:
// blinding with bf1 then bf2 produces the same public key as blinding
// with bf1·bf2 mod ℓ applied once.
func TestMultipleBlinding(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	bf1, _ := GenerateBlindingFactor(rand.Reader)
	bf2, _ := GenerateBlindingFactor(rand.Reader)

	// Sequential blinding: pub -> blind(bf1) -> blind(bf2)
	blindedOnce, _ := BlindPublicKey(pub, bf1)
	blindedTwice, _ := BlindPublicKey(blindedOnce, bf2)

	// Compute combined blinding factor: bf_combined = bf1 · bf2 mod ℓ
	s1, _ := edwards25519.NewScalar().SetBytesWithClamping(bf1)
	s2, _ := edwards25519.NewScalar().SetBytesWithClamping(bf2)
	combined := edwards25519.NewScalar().Multiply(s1, s2)

	// Single blinding with combined factor.
	// We need to use the raw scalar, not a clamped value,
	// so we directly compute b_combined · A.
	A, _ := edwards25519.NewIdentityPoint().SetBytes(pub)
	blindedDirect := edwards25519.NewIdentityPoint().ScalarMult(combined, A)

	if !bytes.Equal(blindedTwice, blindedDirect.Bytes()) {
		t.Error("sequential blinding should equal single blinding with combined factor")
	}

	// Also verify the private key side: blinding priv with bf1 then bf2
	// should produce a key whose public key matches blindedTwice.
	blindedPriv1, _ := BlindPrivateKey(priv, bf1)
	blindedPriv2, _ := BlindPrivateKey(blindedPriv1, bf2)

	if !bytes.Equal(blindedPriv2.Public(), blindedTwice) {
		t.Error("sequential private key blinding should match sequential public key blinding")
	}

	// Sign with doubly-blinded private key, verify with doubly-blinded public key.
	msg := []byte("composable blinding test")
	sig := Sign(blindedPriv2, msg)
	if !Verify(blindedTwice, msg, sig) {
		t.Error("doubly-blinded sign/verify failed")
	}
}

// TestDifferentBlindingFactorsDifferentKeys verifies that different blinding
// factors produce different blinded keys.
func TestDifferentBlindingFactorsDifferentKeys(t *testing.T) {
	pub, _, _ := GenerateKey(rand.Reader)
	bf1, _ := GenerateBlindingFactor(rand.Reader)
	bf2, _ := GenerateBlindingFactor(rand.Reader)

	bp1, _ := BlindPublicKey(pub, bf1)
	bp2, _ := BlindPublicKey(pub, bf2)

	if bp1.Equal(bp2) {
		t.Error("different blinding factors should produce different blinded keys")
	}
}

// TestBlindedKeyIsBlindedFormat verifies internal format detection.
func TestBlindedKeyIsBlindedFormat(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)
	blindedPriv, _ := BlindPrivateKey(priv, bf)

	if len(priv) != PrivateKeySize {
		t.Errorf("normal key length = %d, want %d", len(priv), PrivateKeySize)
	}
	if len(blindedPriv) != blindedPrivateKeySize {
		t.Errorf("blinded key length = %d, want %d", len(blindedPriv), blindedPrivateKeySize)
	}
	if !isValidPrivateKeyLen(priv) {
		t.Error("normal key should be valid")
	}
	if !isValidPrivateKeyLen(blindedPriv) {
		t.Error("blinded key should be valid")
	}
	if isValidPrivateKeyLen(PrivateKey(make([]byte, 32))) {
		t.Error("32-byte key should be invalid")
	}
}

// TestBlindedPrivateKeySeedReturnsScalar verifies that Seed() on a blinded
// key returns the scalar bytes (first 32 bytes).
func TestBlindedPrivateKeySeedReturnsScalar(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)
	blindedPriv, _ := BlindPrivateKey(priv, bf)

	scalar := blindedPriv.Seed()
	if len(scalar) != SeedSize {
		t.Errorf("Seed() on blinded key returned %d bytes, want %d", len(scalar), SeedSize)
	}
	// Should be the first 32 bytes of the blinded key.
	if !bytes.Equal(scalar, blindedPriv[:32]) {
		t.Error("Seed() should return first 32 bytes of blinded key")
	}
}

// TestBlindedSignVerifyMultipleMessages verifies that a single blinded key
// can sign multiple different messages correctly.
func TestBlindedSignVerifyMultipleMessages(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)
	blindedPriv, _ := BlindPrivateKey(priv, bf)
	blindedPub, _ := BlindPublicKey(priv.Public(), bf)

	messages := []string{
		"message one",
		"message two",
		"a longer test message for verification",
		"",
	}
	for _, m := range messages {
		msg := []byte(m)
		sig := Sign(blindedPriv, msg)
		if !Verify(blindedPub, msg, sig) {
			t.Errorf("blinded sign/verify failed for message %q", m)
		}
	}
}
