package red25519

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
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

	b, err := edwards25519.NewScalar().SetBytesWithClamping(blind)
	if err != nil {
		return nil, fmt.Errorf("red25519: invalid blinding factor: %w", err)
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

	b, err := edwards25519.NewScalar().SetBytesWithClamping(blind)
	if err != nil {
		return nil, fmt.Errorf("red25519: invalid blinding factor: %w", err)
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

// isValidPrivateKeyLen reports whether priv has a valid length
// (64 for normal keys, 96 for blinded keys).
func isValidPrivateKeyLen(priv PrivateKey) bool {
	return len(priv) == PrivateKeySize || len(priv) == blindedPrivateKeySize
}
