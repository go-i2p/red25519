package red25519

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

const (
	// BlindingFactorSize is the size, in bytes, of blinding factors.
	BlindingFactorSize = 32

	// blindedPrivateKeySize is the internal size of blinded private keys.
	// Blinded keys use an extended format: scalar(32) || nonce_prefix(32) || pubkey(32).
	// This avoids global state by embedding all signing material in the key itself.
	blindedPrivateKeySize = 96
)

// BlindingFactor is a 32-byte clamped Ed25519 scalar used to blind
// (re-randomize) keypairs. Blinding produces a new keypair that is
// unlinkable to the original yet algebraically related, enabling
// destination blinding in I2P encrypted leasesets.
type BlindingFactor []byte

// GenerateBlindingFactor generates a random blinding factor using entropy
// from rand. If rand is nil, crypto/rand.Reader will be used.
// The output is clamped per Ed25519 convention: low 3 bits
// cleared, bit 254 set, bit 255 cleared.
func GenerateBlindingFactor(rand io.Reader) (BlindingFactor, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	buf := make([]byte, BlindingFactorSize)
	if _, err := io.ReadFull(rand, buf); err != nil {
		return nil, fmt.Errorf("red25519: reading random bytes: %w", err)
	}
	clampBlindingFactor(buf)
	return BlindingFactor(buf), nil
}

// clampBlindingFactor applies Ed25519 scalar clamping in-place:
// clear low 3 bits, set bit 254, clear bit 255.
func clampBlindingFactor(b []byte) {
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
}

// zeroScalarBytes is the canonical encoding of the zero scalar (all zeros).
// Used for constant-time comparison to detect degenerate blinding factors.
var zeroScalarBytes = make([]byte, 32)

// scalarFromBlind converts a BlindingFactor to an edwards25519 scalar.
//
// It uses two decoding paths depending on the input:
//
//   - Canonical path (SetCanonicalBytes): Used for composed factors produced
//     by [ComposeBlindingFactors], which are already reduced mod ℓ. These
//     factors bypass clamping because Multiply produces canonical output.
//
//   - Clamped path (SetBytesWithClamping): Used for factors produced by
//     [GenerateBlindingFactor] or external sources. These are raw 32-byte
//     values that need Ed25519 clamping (clear low 3 bits, set bit 254,
//     clear bit 255) before use as a scalar.
//
// Both paths are mathematically correct; the dual interpretation is needed
// because composed factors (canonical scalars) and generated factors
// (unclamped byte strings) have different representations. Callers should
// not rely on which path is taken — only that the returned scalar is valid.
func scalarFromBlind(blind BlindingFactor) (*edwards25519.Scalar, error) {
	if s, err := edwards25519.NewScalar().SetCanonicalBytes(blind); err == nil {
		return s, nil
	}
	// SetBytesWithClamping requires len(blind) == 32. All callers
	// (BlindPublicKey, BlindPrivateKey, ComposeBlindingFactors) validate
	// the length before calling scalarFromBlind, so this error path is
	// unreachable in normal use. The error is still propagated for
	// defense-in-depth.
	return edwards25519.NewScalar().SetBytesWithClamping(blind)
}

// isZeroScalar reports whether s is the zero scalar, using a constant-time
// comparison to avoid leaking information about the scalar value.
func isZeroScalar(s *edwards25519.Scalar) bool {
	return subtle.ConstantTimeCompare(s.Bytes(), zeroScalarBytes) == 1
}

// BlindPublicKey derives a blinded public key by multiplying the public key
// point A by the blinding factor scalar b: A' = b · A.
// The result is unlinkable to the original public key without knowledge
// of the blinding factor.
func BlindPublicKey(pub PublicKey, blind BlindingFactor) (PublicKey, error) {
	if len(pub) != PublicKeySize {
		return nil, fmt.Errorf("red25519: bad public key length: %d", len(pub))
	}
	if len(blind) != BlindingFactorSize {
		return nil, fmt.Errorf("red25519: bad blinding factor length: %d", len(blind))
	}

	A, err := edwards25519.NewIdentityPoint().SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("red25519: invalid public key: %w", err)
	}

	// Reject small-order input points. Blinding a small-order point
	// produces another small-order point, which would be rejected by
	// Verify. Failing early gives callers a clear error.
	if isSmallOrder(A) {
		return nil, fmt.Errorf("red25519: public key is a small-order point")
	}

	b, err := scalarFromBlind(blind)
	if err != nil {
		return nil, fmt.Errorf("red25519: invalid blinding factor: %w", err)
	}
	if isZeroScalar(b) {
		return nil, fmt.Errorf("red25519: zero blinding factor produces degenerate key")
	}

	// A' = b · A
	blindedA := edwards25519.NewIdentityPoint().ScalarMult(b, A)
	return PublicKey(blindedA.Bytes()), nil
}

// BlindPrivateKey derives a blinded private key by multiplying the private
// scalar a by the blinding factor b: a' = a · b mod ℓ. The resulting key
// can be used with Sign to produce signatures verifiable against the
// corresponding blinded public key (from BlindPublicKey).
//
// Invariant: BlindPublicKey(priv.Public(), bf) == BlindPrivateKey(priv, bf).Public()
//
// The blinded key uses an extended 96-byte internal format so that Sign
// can detect it and use the pre-computed scalar directly (no SHA-512
// re-expansion). The nonce prefix for deterministic signing is derived as
// SHA-512(0xFF || blind || original_prefix) for domain separation.
func BlindPrivateKey(priv PrivateKey, blind BlindingFactor) (PrivateKey, error) {
	if !isValidPrivateKeyLen(priv) {
		return nil, fmt.Errorf("red25519: bad private key length: %d", len(priv))
	}
	if len(blind) != BlindingFactorSize {
		return nil, fmt.Errorf("red25519: bad blinding factor length: %d", len(blind))
	}

	b, err := scalarFromBlind(blind)
	if err != nil {
		return nil, fmt.Errorf("red25519: invalid blinding factor: %w", err)
	}
	if isZeroScalar(b) {
		return nil, fmt.Errorf("red25519: zero blinding factor produces degenerate key")
	}

	// Extract scalar and nonce prefix from the source key.
	a, prefix := expandPrivateKey(priv)

	// a' = a · b mod ℓ
	aPrime := edwards25519.NewScalar().Multiply(a, b)

	// A' = a' · B (derive the blinded public key)
	APrime := edwards25519.NewIdentityPoint().ScalarBaseMult(aPrime)

	// Derive a domain-separated nonce prefix for the blinded key:
	// prefix' = SHA-512(0xFF || blind || original_prefix)[:32]
	derivedPrefix := deriveBlindedPrefix(blind, prefix)

	// Store as 96-byte blinded key: scalar || derived_prefix || pubkey
	blindedPriv := make(PrivateKey, blindedPrivateKeySize)
	copy(blindedPriv[:32], aPrime.Bytes())
	copy(blindedPriv[32:64], derivedPrefix)
	copy(blindedPriv[64:96], APrime.Bytes())

	return blindedPriv, nil
}

// deriveBlindedPrefix computes a domain-separated nonce prefix for blinded
// signing: SHA-512(0xFF || blind || original_prefix), returning the first 32 bytes.
func deriveBlindedPrefix(blind BlindingFactor, originalPrefix []byte) []byte {
	h := sha512.New()
	h.Write([]byte{0xFF})
	h.Write(blind)
	h.Write(originalPrefix)
	digest := h.Sum(nil)
	return digest[:32]
}

// ComposeBlindingFactors computes the scalar product of two blinding
// factors: result = bf1 · bf2 mod ℓ. When used with BlindPublicKey, the
// composed factor produces the same blinded public key as sequential
// blinding with bf1 then bf2:
//
//	composed, _ := ComposeBlindingFactors(bf1, bf2)
//	BlindPublicKey(pub, composed) == BlindPublicKey(BlindPublicKey(pub, bf1), bf2)
//
// For private key blinding, the composed factor yields the same scalar
// and public key but a different deterministic nonce prefix, so signatures
// will differ from those produced by sequential blinding. Both are valid.
//
// The returned [BlindingFactor] is a canonical scalar (reduced mod ℓ),
// not a clamped byte string. When passed to [BlindPublicKey] or
// [BlindPrivateKey], it takes the canonical decoding path in
// scalarFromBlind (SetCanonicalBytes), bypassing clamping. This is
// correct because the Multiply output is already a valid scalar.
func ComposeBlindingFactors(bf1, bf2 BlindingFactor) (BlindingFactor, error) {
	if len(bf1) != BlindingFactorSize {
		return nil, fmt.Errorf("red25519: bad first blinding factor length: %d", len(bf1))
	}
	if len(bf2) != BlindingFactorSize {
		return nil, fmt.Errorf("red25519: bad second blinding factor length: %d", len(bf2))
	}

	s1, err := scalarFromBlind(bf1)
	if err != nil {
		return nil, fmt.Errorf("red25519: invalid first blinding factor: %w", err)
	}
	s2, err := scalarFromBlind(bf2)
	if err != nil {
		return nil, fmt.Errorf("red25519: invalid second blinding factor: %w", err)
	}

	composed := edwards25519.NewScalar().Multiply(s1, s2)
	return BlindingFactor(composed.Bytes()), nil
}

// isValidPrivateKeyLen reports whether priv has a valid length
// (64 for normal keys, 96 for blinded keys).
func isValidPrivateKeyLen(priv PrivateKey) bool {
	return len(priv) == PrivateKeySize || len(priv) == blindedPrivateKeySize
}
