# red25519

[![Go Reference](https://pkg.go.dev/badge/github.com/go-i2p/red25519.svg)](https://pkg.go.dev/github.com/go-i2p/red25519)

RedDSA (randomized, re-randomizable) signature library for Go, built on Ed25519.

## Overview

`red25519` extends standard Ed25519 with **key blinding**: a 32-byte scalar
blinding factor is multiplied into both the private and public key, producing a
new keypair that is unlinkable to the original yet fully functional for signing
and verification. This is used in the I2P network for destination blinding
(encrypted leasesets, etc.).

The API mirrors `crypto/ed25519`, so callers can treat it as a near drop-in
replacement with additional blinding primitives.

> **Note:** `Verify` is intentionally stricter than `crypto/ed25519.Verify`: it
> rejects all small-order public keys (order dividing the cofactor 8), which
> would allow trivial or near-trivial signature forgery. `BlindPublicKey` also
> rejects small-order input points. Normal Ed25519 keypairs are unaffected.

## Features

- **Ed25519 compatible** — unblinded signatures are byte-identical to `crypto/ed25519`
- **Key blinding** — blind both public and private keys with a scalar factor
- **Composable** — sequential blinding with factors `bf1`, `bf2` equals single blinding with `bf1·bf2 mod ℓ`
- **Constant-time** — all scalar operations use `filippo.io/edwards25519` (no branching on secrets)
- **Deterministic signatures** — both normal and blinded signing use deterministic nonces

## Install

```
go get github.com/go-i2p/red25519
```

## Usage

### Standard Signing (Ed25519-Compatible)

```go
package main

import (
    "crypto/rand"
    "fmt"
    "github.com/go-i2p/red25519"
)

func main() {
    // Generate a keypair.
    pub, priv, err := red25519.GenerateKey(rand.Reader)
    if err != nil {
        panic(err)
    }

    // Sign a message.
    msg := []byte("hello, red25519")
    sig := red25519.Sign(priv, msg)

    // Verify the signature.
    ok := red25519.Verify(pub, msg, sig)
    fmt.Println("verified:", ok) // true
}
```

### Key Blinding

```go
package main

import (
    "crypto/rand"
    "fmt"
    "github.com/go-i2p/red25519"
)

func main() {
    // Generate a keypair and a blinding factor.
    pub, priv, _ := red25519.GenerateKey(rand.Reader)
    bf, _ := red25519.GenerateBlindingFactor(rand.Reader)

    // Blind both keys. The blinded keypair is unlinkable to the original.
    blindedPub, _ := red25519.BlindPublicKey(pub, bf)
    blindedPriv, _ := red25519.BlindPrivateKey(priv, bf)

    // Sign with blinded private key, verify with blinded public key.
    msg := []byte("blinded message")
    sig := red25519.Sign(blindedPriv, msg)
    ok := red25519.Verify(blindedPub, msg, sig)
    fmt.Println("blinded verified:", ok) // true

    // The original public key cannot verify the blinded signature.
    ok = red25519.Verify(pub, msg, sig)
    fmt.Println("original verified:", ok) // false
}
```

## API

| Function | Description |
|----------|-------------|
| `GenerateKey(rand)` | Generate a new Ed25519 keypair |
| `NewKeyFromSeed(seed)` | Derive a private key from a 32-byte seed (deterministic) |
| `Sign(privateKey, message)` | Sign a message (works with normal and blinded keys) |
| `Verify(publicKey, message, sig)` | Verify a signature (rejects small-order public keys) |
| `GenerateBlindingFactor(rand)` | Generate a random clamped blinding factor |
| `BlindPublicKey(pub, blind)` | Derive a blinded public key: `A' = b·A` |
| `BlindPrivateKey(priv, blind)` | Derive a blinded private key: `a' = a·b mod ℓ` |
| `ComposeBlindingFactors(bf1, bf2)` | Compose two blinding factors: `bf1·bf2 mod ℓ` |
| `PrivateKey.IsBlinded()` | Reports whether a key was produced by `BlindPrivateKey` |
| `PrivateKey.Scalar()` | Returns the 32-byte private scalar (derived or stored) |

## Dependencies

- [`filippo.io/edwards25519`](https://pkg.go.dev/filippo.io/edwards25519) — constant-time Ed25519 curve operations
- Go standard library (`crypto/sha512`, `crypto/rand`)

## License

See [LICENSE](LICENSE).
