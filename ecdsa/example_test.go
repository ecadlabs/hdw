package ecdsa_test

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

func Example() {
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
	// Output:
	// signature ok: true
	// signature ok: true
}
