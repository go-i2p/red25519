// Package red25519 implements RedDSA (randomized, re-randomizable) signatures
// built on Ed25519. It extends standard Ed25519 with key blinding: a 32-byte
// scalar blinding factor is multiplied into both the private and public key,
// producing a new keypair that is unlinkable to the original yet fully
// functional for signing and verification.
//
// The API mirrors crypto/ed25519, so callers can treat it as a near drop-in
// replacement with additional BlindPublicKey, BlindPrivateKey, and
// BlindingFactor primitives (see blind.go).
//
// Verify is intentionally stricter than crypto/ed25519.Verify: it rejects
// identity-point public keys, which would allow trivial signature forgery.
// Normal Ed25519 keypairs are unaffected.
package red25519

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

// Compile-time check: PrivateKey implements crypto.Signer.
var _ crypto.Signer = PrivateKey(nil)

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
// x must be of type PublicKey; if not, Equal returns false.
// The comparison is constant-time.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pub, xx) == 1
}

// PrivateKey is the type of Ed25519 private keys.
// It has the same layout as crypto/ed25519: 32-byte seed followed by
// 32-byte public key (64 bytes total).
//
// Blinded private keys use an extended 96-byte format:
// scalar(32) || nonce_prefix(32) || pubkey(32). These must only be
// produced by [BlindPrivateKey]; manually constructing a 96-byte
// PrivateKey with invalid scalar bytes will cause Sign to panic.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
// Works for both normal (64-byte) and blinded (96-byte) private keys.
// The returned value has underlying type PublicKey.
func (priv PrivateKey) Public() crypto.PublicKey {
	pub := make(PublicKey, PublicKeySize)
	if len(priv) == blindedPrivateKeySize {
		copy(pub, priv[64:96])
	} else {
		copy(pub, priv[SeedSize:])
	}
	return pub
}

// Sign signs the given message with priv, implementing crypto.Signer.
// Ed25519 performs two passes over messages to be signed and therefore cannot
// handle pre-hashed messages. Thus opts.HashFunc() must return zero to indicate
// the message hasn't been hashed. This can be achieved by passing
// crypto.Hash(0) as the value for opts.
func (priv PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("red25519: cannot sign hashed message")
	}
	return Sign(priv, digest), nil
}

// IsBlinded reports whether priv is a blinded key (produced by [BlindPrivateKey]).
// Blinded keys use a 96-byte internal format and have different semantics for
// [PrivateKey.Seed] and [PrivateKey.Scalar].
func (priv PrivateKey) IsBlinded() bool {
	return len(priv) == blindedPrivateKeySize
}

// Seed returns the private key seed (the first 32 bytes).
// For normal keys, this can be used with [NewKeyFromSeed] to regenerate the key.
//
// WARNING: For blinded keys (produced by [BlindPrivateKey]), the first 32 bytes
// contain the raw scalar, not a seed. Calling NewKeyFromSeed with a blinded
// key's Seed will NOT recreate the blinded key — it will produce an unrelated
// normal key. Use [PrivateKey.IsBlinded] to check, and [PrivateKey.Scalar] to
// retrieve the blinded scalar explicitly.
func (priv PrivateKey) Seed() []byte {
	seed := make([]byte, SeedSize)
	copy(seed, priv[:SeedSize])
	return seed
}

// Scalar returns the private scalar as a 32-byte canonical encoding.
// For blinded keys (produced by [BlindPrivateKey]), this is the stored
// blinded scalar a' = a·b mod ℓ. For normal keys, this is derived by
// expanding the seed via SHA-512 and clamping, matching the Ed25519
// key derivation procedure.
//
// The returned scalar is the secret signing exponent. Handle it with the
// same care as the private key itself.
func (priv PrivateKey) Scalar() []byte {
	s, _ := expandPrivateKey(priv)
	out := make([]byte, 32)
	copy(out, s.Bytes())
	return out
}

// Equal reports whether priv and x have the same value.
// x must be of type PrivateKey; if not, Equal returns false.
// The comparison is constant-time.
func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(priv, xx) == 1
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}
	priv := NewKeyFromSeed(seed)
	return priv.Public().(PublicKey), priv, nil
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
//
// Panics if a 96-byte key contains invalid scalar bytes (i.e., bytes that
// are not a canonical encoding of a scalar mod ℓ). This can only happen
// if a 96-byte PrivateKey was constructed manually rather than through
// [BlindPrivateKey], which always produces valid scalar bytes.
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
		panic(fmt.Sprintf("red25519: bad private key length: %d", len(privateKey)))
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

	pubKey := privateKey.Public().(PublicKey)

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
//
// Unlike [crypto/ed25519.Verify], this function rejects the identity point
// as a public key. The identity point allows trivial forgery (S·B = R for
// any message), so rejecting it is a defense-in-depth measure. Normal
// Ed25519 keypairs are unaffected by this check.
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

	// Reject the identity point as a public key. If A is the identity,
	// then k·A = identity for all k, so the verification equation reduces
	// to S·B = R, allowing trivial forgery on any message.
	if A.Equal(edwards25519.NewIdentityPoint()) == 1 {
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
	// Use the raw signature bytes (sig[:32]) rather than re-encoding R,
	// matching RFC 8032 §5.1.7 and crypto/ed25519. Since non-canonical
	// encodings are rejected above, sig[:32] == R.Bytes() for all
	// accepted inputs.
	kHash := sha512.New()
	kHash.Write(sig[:32])
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
