/*
Package ex25519 provides operations with expanded (64 bit post-hash) ed25519 private keys.
These keys can't be serialized as they aren't compatible with existing protocols and libraries.
The package sole purpose is to add signing and public key derivation interface to BIP32-ED25519 derived keys.
*/
package ex25519

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"io"

	"filippo.io/edwards25519"
)

const (
	ExpandedKeySize = 64
	PrivateKeySize  = 96
	PublicKeySize   = 32
	SignatureSize   = 64
)

var ErrKeySize = errors.New("ex25519: bad private key size")

type PrivateKey []byte

func (p PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	return ok && bytes.Equal(p, xx)
}

func (p PrivateKey) Public() crypto.PublicKey {
	out := make([]byte, PublicKeySize)
	copy(out, p[64:])
	return ed25519.PublicKey(out)
}

func (priv PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return Sign(priv, message), nil
}

func derivePublic(priv []byte) []byte {
	p, err := edwards25519.NewScalar().SetBytesWithClamping(priv[:32])
	if err != nil {
		panic(err)
	}
	point := (&edwards25519.Point{}).ScalarBaseMult(p)
	return point.Bytes()
}

func NewKeyFromBytes(src []byte) (PrivateKey, error) {
	if len(src) != ExpandedKeySize {
		return nil, ErrKeySize
	}

	pub := derivePublic(src)
	priv := make([]byte, PrivateKeySize)
	copy(priv, src)
	copy(priv[64:], pub)
	return priv, nil
}

func Sign(pk PrivateKey, message []byte) []byte {
	if len(pk) != PrivateKeySize {
		panic("ex25519: bad private key size")
	}

	priv := pk[:64]
	pub := pk[64:]

	s, err := edwards25519.NewScalar().SetBytesWithClamping(priv[:32])
	if err != nil {
		panic(err)
	}
	prefix := priv[32:]

	mh := sha512.New()
	mh.Write(prefix)
	mh.Write(message)
	messageDigest := make([]byte, 0, sha512.Size)
	messageDigest = mh.Sum(messageDigest)
	r, err := edwards25519.NewScalar().SetUniformBytes(messageDigest)
	if err != nil {
		panic(err)
	}

	R := (&edwards25519.Point{}).ScalarBaseMult(r)

	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(pub)
	kh.Write(message)
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic(err)
	}

	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)

	signature := make([]byte, SignatureSize)
	copy(signature[:32], R.Bytes())
	copy(signature[32:], S.Bytes())

	return signature
}
