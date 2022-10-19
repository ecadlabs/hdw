# HDW

```go
import "github.com/ecadlabs/hdw/ecdsa"
```

The module implements

* [SLIP-10: Universal private key derivation from master private key](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
* [BIP32-Ed25519: Hierarchical Deterministic Keys over a Non-linear Keyspace](doc/Ed25519_BIP_Final.pdf)
* A subset of  [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) (master seed from mnemonic generation only)

## Master seed generation

```go
	mnemonic := "nel mezzo del cammin di nostra vita mi ritrovai per una selva oscura"
	seed := hdw.NewSeedFromMnemonic(mnemonic, "")
```

## SLIP-10 / ECDSA

Directly supported curves are Secp256k1 and NIST P-256. The `ecdsa` package is agnostic to the curve implementation as the curve is detected by its parameters. Other curves can be used as well  with custom HMAC key phrase, like "curve_name seed" (see the package documentation).

```go
package main

import (
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ecadlabs/hdw"
	"github.com/ecadlabs/hdw/ecdsa"
)

var seedData = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

func main() {
	// alternatively use hdw.NewSeedFromMnemonic
	seed, err := hex.DecodeString(seedData)
	if err != nil {
		panic(err)
	}

	// generate the root key
	root, err := ecdsa.NewKeyFromSeed(seed, elliptic.P256())
	if err != nil {
		panic(err)
	}

	path := hdw.Path{0, 1, 2}
	// generate the derivative child private key
	priv, err := root.DerivePath(path)
	if err != nil {
		panic(err)
	}

	digest := sha256.Sum256([]byte("text"))
	sig, err := priv.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		panic(err)
	}

	// get the corresponding public key
	pub := priv.Public()

	// verify the signature
	ok := stdecdsa.VerifyASN1(pub.(*stdecdsa.PublicKey), digest[:], sig)
	fmt.Printf("signature ok: %t\n", ok)

	// derive the public key from the root's public
	pub2, err := root.ExtendedPublic().DerivePath(path)
	if err != nil {
		panic(err)
	}
	// verify the signature
	ok = stdecdsa.VerifyASN1(pub2.Naked().(*stdecdsa.PublicKey), digest[:], sig)
	fmt.Printf("signature ok: %t\n", ok)
}
```

## SLIP-10 / Ed25519

```go
package main

import (
	"crypto"
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ecadlabs/hdw"
	"github.com/ecadlabs/hdw/ed25519"
)

var seedData = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

func main() {
	// alternatively use hdw.NewSeedFromMnemonic
	seed, err := hex.DecodeString(seedData)
	if err != nil {
		panic(err)
	}

	// generate the root key
	root := ed25519.NewKeyFromSeed(seed)

	path := hdw.Path{0 | hdw.Hard, 1 | hdw.Hard, 2 | hdw.Hard}
	// generate the derivative child private key
	priv, err := root.DerivePath(path)
	if err != nil {
		panic(err)
	}

	digest := sha256.Sum256([]byte("text"))
	sig, err := priv.Sign(rand.Reader, digest[:], crypto.Hash(0))
	if err != nil {
		panic(err)
	}

	// get the corresponding public key
	pub := priv.Public()

	// verify the signature
	ok := stded25519.Verify(pub.(stded25519.PublicKey), digest[:], sig)
	fmt.Printf("signature ok: %t\n", ok)
}
```

## BIP32-Ed25519

Different implementations of this algorithm may have some deviations from the paper in the root key generation step. `bip25519` package implements some of them. Specifically it can use HMAC instead of plain SHA hash (as in Ledger and some other implementations) then it can rehash the result if the seed gives an unusable value (Ledger also does this) instead of returning nil or just clear undesired bits (not recommended).

### Warning

**Despite in the HMAC+Retry mode the result is identical to one produced by Speculos emulator it's still incompatible with the Ledger firmware**

### Standard mode

```go
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ecadlabs/hdw"
	"github.com/ecadlabs/hdw/bip25519"
)

var seedData = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

func main() {
	// alternatively use hdw.NewSeedFromMnemonic
	seed, err := hex.DecodeString(seedData)
	if err != nil {
		panic(err)
	}

	// generate the root key
	root := bip25519.NewKeyFromSeed(seed, nil)
	if root == nil {
		panic("unusable seed")
	}

	path := hdw.Path{0, 1, 2}
	// generate the derivative child private key
	priv, err := root.DerivePath(path)
	if err != nil {
		panic(err)
	}

	digest := sha256.Sum256([]byte("text"))
	sig, err := priv.Sign(rand.Reader, digest[:], crypto.Hash(0))
	if err != nil {
		panic(err)
	}

	// get the corresponding public key
	pub := priv.Public()

	// verify the signature
	ok := ed25519.Verify(pub.(ed25519.PublicKey), digest[:], sig)
	fmt.Printf("signature ok: %t\n", ok)

	// derive the public key from the root's public
	pub2, err := root.ExtendedPublic().DerivePath(path)
	if err != nil {
		panic(err)
	}
	// verify the signature
	ok = ed25519.Verify(pub2.Naked().(ed25519.PublicKey), digest[:], sig)
	fmt.Printf("signature ok: %t\n", ok)
}
```

### HMAC mode

The same as above except the root key generation step:

```go
// generate the root key
root := bip25519.NewKeyFromSeed(seed, &bip25519.Options{Mode: bip25519.ModeRetry, HMAC: true})
// no need for nil check
```

