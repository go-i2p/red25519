// Package red25519 implements RedDSA (randomized, re-randomizable) signatures
// built on Ed25519. It extends standard Ed25519 with key blinding: a 32-byte
// scalar blinding factor is multiplied into both the private and public key,
// producing a new keypair that is unlinkable to the original yet fully
// functional for signing and verification.
//
// The API mirrors crypto/ed25519, so callers can treat it as a near drop-in
// replacement with additional BlindPublicKey, BlindPrivateKey, and
// BlindingFactor primitives (see blind.go).
package red25519

import (
	"crypto/sha512"
	"io"

	"filippo.io/edwards25519"
)

const (
	// PublicKeySize is the size, in bytes, of public keys.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds,
	// which are used to derive the full private key.
	SeedSize = 32
)

// PublicKey is the type of Ed25519 public keys (32-byte compressed point).
type PublicKey []byte

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x PublicKey) bool {
	if len(pub) != len(x) {
		return false
	}
	for i := range pub {
		if pub[i] != x[i] {
			return false
		}
	}
	return true
}

// PrivateKey is the type of Ed25519 private keys.
// It has the same layout as crypto/ed25519: 32-byte seed followed by
// 32-byte public key.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
// Works for both normal (64-byte) and blinded (96-byte) private keys.
func (priv PrivateKey) Public() PublicKey {
	pub := make(PublicKey, PublicKeySize)
	if len(priv) == blindedPrivateKeySize {
		copy(pub, priv[64:96])
	} else {
		copy(pub, priv[SeedSize:])
	}
	return pub
}

// Seed returns the private key seed (the first 32 bytes).
// For normal keys, this can be used with NewKeyFromSeed to regenerate the key.
// For blinded keys, the first 32 bytes contain the raw scalar, not a seed.
func (priv PrivateKey) Seed() []byte {
	seed := make([]byte, SeedSize)
	copy(seed, priv[:SeedSize])
	return seed
}

// Equal reports whether priv and x have the same value.
func (priv PrivateKey) Equal(x PrivateKey) bool {
	if len(priv) != len(x) {
		return false
	}
	for i := range priv {
		if priv[i] != x[i] {
			return false
		}
	}
	return true
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}
	priv := NewKeyFromSeed(seed)
	return priv.Public(), priv, nil
}

// NewKeyFromSeed calculates a private key from a seed. Panics if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032; for most uses, GenerateKey should be preferred.
func NewKeyFromSeed(seed []byte) PrivateKey {
	if len(seed) != SeedSize {
		panic("red25519: bad seed length")
	}

	h := sha512.Sum512(seed)

	// Clamp the scalar according to Ed25519 convention.
	// SetBytesWithClamping does this for us.
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("red25519: internal error clamping scalar: " + err.Error())
	}

	// A = s * B (base point multiplication)
	A := edwards25519.NewIdentityPoint().ScalarBaseMult(s)

	priv := make(PrivateKey, PrivateKeySize)
	copy(priv[:SeedSize], seed)
	copy(priv[SeedSize:], A.Bytes())
	return priv
}

// expandPrivateKey extracts the signing scalar and nonce prefix from a
// private key. For normal (64-byte) keys, SHA-512 expands the seed to
// produce (clamped scalar, prefix). For blinded (96-byte) keys, the scalar
// and prefix are stored directly.
func expandPrivateKey(priv PrivateKey) (scalar *edwards25519.Scalar, prefix []byte) {
	if len(priv) == blindedPrivateKeySize {
		// Blinded key: scalar stored directly as canonical bytes.
		s, err := edwards25519.NewScalar().SetCanonicalBytes(priv[:32])
		if err != nil {
			panic("red25519: invalid blinded key scalar: " + err.Error())
		}
		prefix = make([]byte, 32)
		copy(prefix, priv[32:64])
		return s, prefix
	}

	// Normal key: expand seed via SHA-512.
	h := sha512.Sum512(priv[:SeedSize])
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("red25519: internal error clamping scalar: " + err.Error())
	}
	prefix = make([]byte, 32)
	copy(prefix, h[32:64])
	return s, prefix
}

// Sign signs the message with privateKey and returns a 64-byte signature.
// It works with both normal keys (from GenerateKey/NewKeyFromSeed) and
// blinded keys (from BlindPrivateKey). For blinded keys, the pre-computed
// scalar is used directly and the nonce is derived from the embedded
// domain-separated prefix.
func Sign(privateKey PrivateKey, message []byte) []byte {
	if !isValidPrivateKeyLen(privateKey) {
		panic("red25519: bad private key length")
	}

	// Extract scalar and nonce prefix (works for both normal and blinded keys).
	a, prefix := expandPrivateKey(privateKey)

	// Deterministic nonce: r = SHA-512(prefix || message), reduced mod l.
	nHash := sha512.New()
	nHash.Write(prefix)
	nHash.Write(message)
	nDigest := nHash.Sum(nil)

	r, err := edwards25519.NewScalar().SetUniformBytes(nDigest)
	if err != nil {
		panic("red25519: internal error reducing nonce: " + err.Error())
	}

	// R = r * B
	R := edwards25519.NewIdentityPoint().ScalarBaseMult(r)

	pubKey := privateKey.Public()

	// k = SHA-512(R || pubkey || message), reduced mod l.
	kHash := sha512.New()
	kHash.Write(R.Bytes())
	kHash.Write(pubKey)
	kHash.Write(message)
	kDigest := kHash.Sum(nil)

	k, err := edwards25519.NewScalar().SetUniformBytes(kDigest)
	if err != nil {
		panic("red25519: internal error reducing challenge: " + err.Error())
	}

	// S = r + k*a mod l
	S := edwards25519.NewScalar().MultiplyAdd(k, a, r)

	sig := make([]byte, SignatureSize)
	copy(sig[:32], R.Bytes())
	copy(sig[32:], S.Bytes())
	return sig
}

// Verify reports whether sig is a valid signature of message by publicKey.
// It returns false for malformed inputs.
func Verify(publicKey PublicKey, message []byte, sig []byte) bool {
	if len(publicKey) != PublicKeySize {
		return false
	}
	if len(sig) != SignatureSize {
		return false
	}

	// Decode public key point A.
	A, err := edwards25519.NewIdentityPoint().SetBytes(publicKey)
	if err != nil {
		return false
	}

	// Parse R from first 32 bytes of signature.
	// We verify R is a valid point encoding.
	R, err := edwards25519.NewIdentityPoint().SetBytes(sig[:32])
	if err != nil {
		return false
	}

	// Parse S from last 32 bytes of signature.
	// Reject non-canonical scalars (>= l).
	S, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	// k = SHA-512(R || publicKey || message), reduced mod l.
	kHash := sha512.New()
	kHash.Write(R.Bytes())
	kHash.Write(publicKey)
	kHash.Write(message)
	kDigest := kHash.Sum(nil)

	k, err := edwards25519.NewScalar().SetUniformBytes(kDigest)
	if err != nil {
		return false
	}

	// Check: S*B == R + k*A
	// Equivalently: S*B - k*A == R
	// Use VarTimeDoubleScalarBaseMult for efficiency: computes a*A + b*B.
	// We want to check S*B - k*A == R, i.e., (-k)*A + S*B == R.
	negK := edwards25519.NewScalar().Negate(k)
	check := edwards25519.NewIdentityPoint().VarTimeDoubleScalarBaseMult(negK, A, S)

	return check.Equal(R) == 1
}
