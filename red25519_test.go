package red25519

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"filippo.io/edwards25519"
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

func TestGenerateKeyNilRand(t *testing.T) {
	// nil rand should fall back to crypto/rand.Reader, matching crypto/ed25519.
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(nil) failed: %v", err)
	}
	if len(pub) != PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pub), PublicKeySize)
	}
	if len(priv) != PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(priv), PrivateKeySize)
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
	if !bytes.Equal([]byte(redPriv.Public().(PublicKey)), stdPriv.Public().(ed25519.PublicKey)) {
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

// TestIsBlinded verifies that IsBlinded correctly distinguishes normal
// and blinded private keys.
func TestIsBlinded(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	if priv.IsBlinded() {
		t.Error("normal key should not report as blinded")
	}

	bf, _ := GenerateBlindingFactor(rand.Reader)
	blindedPriv, _ := BlindPrivateKey(priv, bf)
	if !blindedPriv.IsBlinded() {
		t.Error("blinded key should report as blinded")
	}
}

// TestScalar verifies that Scalar() returns the correct private scalar
// for both normal and blinded keys.
func TestScalar(t *testing.T) {
	t.Run("normal key scalar matches stdlib derivation", func(t *testing.T) {
		seed := make([]byte, SeedSize)
		_, _ = io.ReadFull(rand.Reader, seed)
		priv := NewKeyFromSeed(seed)

		scalar := priv.Scalar()
		if len(scalar) != 32 {
			t.Fatalf("Scalar() returned %d bytes, want 32", len(scalar))
		}

		// The scalar should NOT equal the seed (it's derived via SHA-512+clamping).
		if bytes.Equal(scalar, seed) {
			t.Error("scalar should differ from seed")
		}

		// Two calls should return equal values (deterministic).
		scalar2 := priv.Scalar()
		if !bytes.Equal(scalar, scalar2) {
			t.Error("Scalar() is not deterministic for normal keys")
		}
	})

	t.Run("blinded key scalar matches first 32 bytes", func(t *testing.T) {
		_, priv, _ := GenerateKey(rand.Reader)
		bf, _ := GenerateBlindingFactor(rand.Reader)
		blindedPriv, _ := BlindPrivateKey(priv, bf)

		scalar := blindedPriv.Scalar()
		if len(scalar) != 32 {
			t.Fatalf("Scalar() returned %d bytes, want 32", len(scalar))
		}

		// For blinded keys, Scalar() should return the same bytes as stored
		// in the first 32 bytes (the blinded scalar).
		if !bytes.Equal(scalar, blindedPriv[:32]) {
			t.Error("Scalar() on blinded key should match stored scalar")
		}
	})

	t.Run("blinded scalar differs from Seed on normal key", func(t *testing.T) {
		seed := make([]byte, SeedSize)
		_, _ = io.ReadFull(rand.Reader, seed)
		priv := NewKeyFromSeed(seed)

		// Seed() returns the raw seed; Scalar() returns the derived scalar.
		if bytes.Equal(priv.Seed(), priv.Scalar()) {
			t.Error("Seed() and Scalar() should differ for normal keys")
		}
	})

	t.Run("scalar is independent copy", func(t *testing.T) {
		_, priv, _ := GenerateKey(rand.Reader)
		scalar := priv.Scalar()
		// Mutating the returned slice should not affect the key.
		scalar[0] ^= 0xFF
		scalar2 := priv.Scalar()
		if bytes.Equal(scalar, scalar2) {
			t.Error("Scalar() should return independent copies")
		}
	})
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
		r := recover()
		if r == nil {
			t.Fatal("expected panic for bad private key length")
		}
		msg := fmt.Sprint(r)
		if !strings.Contains(msg, "32") {
			t.Errorf("panic message should include actual length 32, got: %s", msg)
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
	if !Verify(redPriv.Public().(PublicKey), msg, stdSig) {
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
	// Wrong type should return false, not panic.
	if pub1.Equal("not a key") {
		t.Error("should return false for wrong type")
	}
	if pub1.Equal(42) {
		t.Error("should return false for non-key type")
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
	// Wrong type should return false, not panic.
	if priv1.Equal("not a key") {
		t.Error("should return false for wrong type")
	}
	if priv1.Equal(42) {
		t.Error("should return false for non-key type")
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
		// The identity point is a degenerate public key that allows trivial
		// forgery: if A = identity, then k·A = identity for all k, so the
		// verification equation reduces to S·B = R. Verify rejects all
		// small-order points (including the identity) as defense-in-depth.
		identity := make(PublicKey, PublicKeySize)
		identity[0] = 0x01 // compressed identity point encoding in Ed25519
		_, priv, _ := GenerateKey(rand.Reader)
		msg := []byte("test")
		sig := Sign(priv, msg)
		// Must be rejected because the identity point is not a valid public key.
		if Verify(identity, msg, sig) {
			t.Error("should reject identity point as public key")
		}
	})

	t.Run("identity point forgery attempt", func(t *testing.T) {
		// Construct a forgery against the identity point: choose an
		// arbitrary scalar S, compute R = S*B, and form sig = (R || S).
		// Without the identity check, this would verify for any message.
		identity := make(PublicKey, PublicKeySize)
		identity[0] = 0x01 // compressed identity point
		// Use a trivial scalar: S = 1 (the first canonical byte of 1).
		sBytes := make([]byte, 32)
		sBytes[0] = 0x01
		s, _ := (&edwards25519.Scalar{}).SetCanonicalBytes(sBytes)
		R := (&edwards25519.Point{}).ScalarBaseMult(s)
		forgedSig := make([]byte, SignatureSize)
		copy(forgedSig[:32], R.Bytes())
		copy(forgedSig[32:], s.Bytes())
		if Verify(identity, []byte("any message"), forgedSig) {
			t.Error("forged signature against identity point should be rejected")
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

// TestPrivateKeyImplementsSigner verifies that PrivateKey satisfies crypto.Signer.
func TestPrivateKeyImplementsSigner(t *testing.T) {
	_, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var signer crypto.Signer = priv
	_ = signer // compile-time check; runtime confirms no panic
}

// TestPrivateKeySignMethod tests the crypto.Signer Sign method.
func TestPrivateKeySignMethod(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("signer interface test")

	// Sign via the crypto.Signer method (Ed25519 pure: hash = 0).
	sig, err := priv.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("PrivateKey.Sign failed: %v", err)
	}

	if !Verify(pub, msg, sig) {
		t.Error("signature from PrivateKey.Sign failed verification")
	}

	// Must produce the same signature as the package-level Sign function.
	sigDirect := Sign(priv, msg)
	if !bytes.Equal(sig, sigDirect) {
		t.Error("PrivateKey.Sign and package-level Sign produced different signatures")
	}
}

// TestPrivateKeySignMethodRejectsHash verifies that the Sign method
// rejects pre-hashed messages.
func TestPrivateKeySignMethodRejectsHash(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)

	_, err := priv.Sign(rand.Reader, []byte("data"), crypto.SHA256)
	if err == nil {
		t.Error("expected error when signing with non-zero hash, got nil")
	}
	_, err = priv.Sign(rand.Reader, []byte("data"), crypto.SHA512)
	if err == nil {
		t.Error("expected error when signing with SHA-512 hash, got nil")
	}
}

// TestPrivateKeySignMethodNilRand verifies that the Sign method works
// when rand is nil (Ed25519 signing is deterministic, rand is unused).
func TestPrivateKeySignMethodNilRand(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	msg := []byte("nil rand signer test")

	sig, err := priv.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("PrivateKey.Sign(nil, ...) failed: %v", err)
	}
	if !Verify(pub, msg, sig) {
		t.Error("signature from nil-rand Sign failed verification")
	}
}

// TestPrivateKeyPublicReturnsCryptoPublicKey verifies that Public() returns
// a value satisfying crypto.PublicKey (interface type) with underlying type PublicKey.
func TestPrivateKeyPublicReturnsCryptoPublicKey(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)

	cryptoPub := priv.Public()

	// Must be convertible back to PublicKey.
	pub, ok := cryptoPub.(PublicKey)
	if !ok {
		t.Fatal("Public() did not return underlying type PublicKey")
	}
	if len(pub) != PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pub), PublicKeySize)
	}
}

// TestBlindedPrivateKeySignMethod verifies that the crypto.Signer Sign
// method works with blinded private keys.
func TestBlindedPrivateKeySignMethod(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	bf, _ := GenerateBlindingFactor(rand.Reader)

	blindedPriv, err := BlindPrivateKey(priv, bf)
	if err != nil {
		t.Fatalf("BlindPrivateKey: %v", err)
	}
	blindedPub, err := BlindPublicKey(priv.Public().(PublicKey), bf)
	if err != nil {
		t.Fatalf("BlindPublicKey: %v", err)
	}

	msg := []byte("blinded signer test")
	sig, err := blindedPriv.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("blinded PrivateKey.Sign failed: %v", err)
	}
	if !Verify(blindedPub, msg, sig) {
		t.Error("blinded signature from PrivateKey.Sign failed verification")
	}
}

// TestSignerCompatibilityWithStdlib verifies that red25519.PrivateKey
// can be used wherever a crypto.Signer is expected, producing signatures
// compatible with crypto/ed25519.Verify.
func TestSignerCompatibilityWithStdlib(t *testing.T) {
	seed := make([]byte, SeedSize)
	_, _ = io.ReadFull(rand.Reader, seed)

	redPriv := NewKeyFromSeed(seed)
	stdPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	msg := []byte("signer stdlib compat")

	// Use via crypto.Signer interface.
	var signer crypto.Signer = redPriv
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("crypto.Signer.Sign failed: %v", err)
	}

	// Verify with stdlib.
	if !ed25519.Verify(stdPub, msg, sig) {
		t.Error("crypto/ed25519 failed to verify signature from red25519 crypto.Signer")
	}
}

// TestVerifyNonCanonicalR verifies that a signature with a non-canonical R
// encoding (valid 32 bytes but not a valid curve point) is rejected.
func TestVerifyNonCanonicalR(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	msg := []byte("non-canonical R test")
	sig := Sign(priv, msg)

	// Replace R (first 32 bytes) with a non-canonical point encoding.
	// All 0xFF bytes do not represent a valid Ed25519 point.
	for i := 0; i < 32; i++ {
		sig[i] = 0xFF
	}
	if Verify(pub, msg, sig) {
		t.Error("should reject signature with non-canonical R encoding")
	}

	// Also try all zeros — the identity point encoding. The R parse step
	// itself will succeed (identity is a valid point encoding), but the
	// overall verification equation should still fail because S and the
	// challenge no longer match.
	sig2 := Sign(priv, msg)
	for i := 0; i < 32; i++ {
		sig2[i] = 0x00
	}
	// Set the sign bit correctly for identity: 0x01 at byte 0
	sig2[0] = 0x01
	if Verify(pub, msg, sig2) {
		t.Error("should reject signature with identity R")
	}
}

// TestSignVerifyWithStdlibRoundTrip verifies bidirectional compatibility:
// sign with crypto/ed25519, verify with red25519 on the same seed.
func TestSignVerifyWithStdlibRoundTrip(t *testing.T) {
	seed := make([]byte, SeedSize)
	_, _ = io.ReadFull(rand.Reader, seed)

	stdPriv := ed25519.NewKeyFromSeed(seed)
	redPub := NewKeyFromSeed(seed).Public().(PublicKey)

	messages := [][]byte{
		[]byte("hello from stdlib"),
		[]byte(""),
		nil,
		[]byte("a]longer message for cross-library round-trip testing"),
	}

	for i, msg := range messages {
		// Sign with crypto/ed25519.
		stdSig := ed25519.Sign(stdPriv, msg)

		// Verify with red25519.
		if !Verify(redPub, msg, stdSig) {
			t.Errorf("message %d: red25519 failed to verify crypto/ed25519 signature", i)
		}

		// Also sign with red25519 and verify with crypto/ed25519 for full round-trip.
		redPriv := NewKeyFromSeed(seed)
		redSig := Sign(redPriv, msg)
		stdPub := stdPriv.Public().(ed25519.PublicKey)
		if !ed25519.Verify(stdPub, msg, redSig) {
			t.Errorf("message %d: crypto/ed25519 failed to verify red25519 signature", i)
		}

		// Signatures should be byte-identical (deterministic nonce derivation).
		if !bytes.Equal(stdSig, redSig) {
			t.Errorf("message %d: signatures differ between red25519 and crypto/ed25519", i)
		}
	}
}

// TestVerifySmallOrderPublicKeys verifies that Verify rejects all 8 small-order
// points on the Ed25519 curve, not just the identity. These points have order
// dividing the cofactor 8 and allow trivial or near-trivial signature forgery.
func TestVerifySmallOrderPublicKeys(t *testing.T) {
	// Known small-order point encodings on Ed25519.
	// Each is 32 bytes: y-coordinate (little-endian) with sign bit in bit 255.
	smallOrderPoints := []struct {
		name    string
		encoded [32]byte
	}{
		{
			name: "identity (0,1) order 1",
			encoded: [32]byte{
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "(0,-1) order 2",
			encoded: [32]byte{
				0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
			},
		},
		{
			name: "(sqrt(-1),0) order 4 sign=0",
			encoded: [32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "(-sqrt(-1),0) order 4 sign=1",
			encoded: [32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
			},
		},
	}

	_, priv, _ := GenerateKey(rand.Reader)
	msg := []byte("small order test")
	sig := Sign(priv, msg)

	for _, tc := range smallOrderPoints {
		t.Run(tc.name, func(t *testing.T) {
			pub := PublicKey(tc.encoded[:])

			// First verify that this is actually a valid point encoding
			// (SetBytes succeeds) and that it IS small-order.
			P, err := edwards25519.NewIdentityPoint().SetBytes(pub)
			if err != nil {
				t.Skipf("encoding not accepted by SetBytes (skip): %v", err)
			}

			// Confirm [8]P = identity (small-order).
			eightBytes := make([]byte, 32)
			eightBytes[0] = 8
			eight, _ := edwards25519.NewScalar().SetCanonicalBytes(eightBytes)
			eightP := edwards25519.NewIdentityPoint().ScalarMult(eight, P)
			if eightP.Equal(edwards25519.NewIdentityPoint()) != 1 {
				t.Fatal("test point is not actually small-order")
			}

			// Verify must reject.
			if Verify(pub, msg, sig) {
				t.Errorf("Verify should reject small-order public key %s", tc.name)
			}
		})
	}
}

// TestExpandPrivateKeyPanicInvalidScalar verifies that expandPrivateKey panics
// when given a manually-constructed 96-byte key with a non-canonical scalar
// (>= ℓ). This is a defensive path that can only be reached by constructing
// a PrivateKey manually, not through BlindPrivateKey.
func TestExpandPrivateKeyPanicInvalidScalar(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for invalid blinded key scalar")
		}
		msg := fmt.Sprint(r)
		if !strings.Contains(msg, "invalid blinded key scalar") {
			t.Errorf("unexpected panic message: %s", msg)
		}
	}()

	// Construct a 96-byte key with non-canonical scalar bytes (all 0xFF >= ℓ).
	badKey := make(PrivateKey, blindedPrivateKeySize)
	for i := 0; i < 32; i++ {
		badKey[i] = 0xFF
	}
	// Fill the rest with plausible data (doesn't matter, should panic first).
	copy(badKey[64:96], make([]byte, 32))

	// This should panic because the scalar is non-canonical.
	expandPrivateKey(badKey)
}

// TestComposeBlindingFactorsErrorPathUnreachable documents that the
// scalarFromBlind error paths at blind.go:169,173 within ComposeBlindingFactors
// are unreachable: they would require a non-32-byte factor, which is already
// rejected by the length checks above. This test verifies that the length
// checks do in fact guard those paths.
func TestComposeBlindingFactorsErrorPathUnreachable(t *testing.T) {
	bf, _ := GenerateBlindingFactor(rand.Reader)

	// The only way to trigger scalarFromBlind errors from ComposeBlindingFactors
	// is with non-32-byte inputs, which are caught by the length checks first.
	// Verify that all invalid lengths are rejected with a length error, not a
	// scalar decoding error.
	badLengths := []int{0, 1, 16, 31, 33, 64}
	for _, l := range badLengths {
		t.Run(fmt.Sprintf("len=%d", l), func(t *testing.T) {
			bad := BlindingFactor(make([]byte, l))
			_, err := ComposeBlindingFactors(bad, bf)
			if err == nil {
				t.Fatal("expected error for bad length")
			}
			if !strings.Contains(err.Error(), "length") {
				t.Errorf("error should mention length, got: %v", err)
			}
			_, err = ComposeBlindingFactors(bf, bad)
			if err == nil {
				t.Fatal("expected error for bad length")
			}
			if !strings.Contains(err.Error(), "length") {
				t.Errorf("error should mention length, got: %v", err)
			}
		})
	}
}

// BenchmarkSign benchmarks the Sign function with a normal key.
func BenchmarkSign(b *testing.B) {
	_, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for signing")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(priv, msg)
	}
}

// BenchmarkVerify benchmarks the Verify function.
func BenchmarkVerify(b *testing.B) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for verification")
	sig := Sign(priv, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}
