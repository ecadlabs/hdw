package bip25519_test

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

func Example() {
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
	// Output:
	// signature ok: true
	// signature ok: true
}
