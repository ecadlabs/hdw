/*
Package ed25519 deals with SLIP-10 Ed25519 keys.
Unlike ECDSA SLIP-10 keys these keys can be used for hardened derivation only.
*/
package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ecadlabs/hdw"
)

const ed25519Key = "ed25519 seed"

const (
	// MinSeedSize is the minimal allowed seed byte length
	MinSeedSize = 16
	// MaxSeedSize is the maximal allowed seed byte length
	MaxSeedSize = 64
)

var (
	// ErrNonHardened is returned when an attempt to use non hardened path was made
	ErrNonHardened = errors.New("ed25519: non hardened derivation")
	// ErrPublic is returned when an attempt to derive a public key's child was made
	ErrPublic = errors.New("ed25519: can't use public key for derivation")
)

// PrivateKey is the extended Ed25519 private key. It implements hdw.PrivateKey
type PrivateKey struct {
	ed25519.PrivateKey
	ChainCode []byte
}

func hmacSha512(data []byte, key []byte) []byte {
	hmac := hmac.New(sha512.New, key)
	hmac.Write(data)
	return hmac.Sum(nil)
}

// Derive returns a child key of the receiver using a single index
func (s *PrivateKey) Derive(index uint32) (hdw.PrivateKey, error) {
	data := make([]byte, 37)
	if index&hdw.Hard == 0 {
		return nil, ErrNonHardened
	}
	copy(data[1:], s.Seed())
	binary.BigEndian.PutUint32(data[33:], index)
	sum := hmacSha512(data, s.ChainCode)
	return &PrivateKey{
		PrivateKey: ed25519.NewKeyFromSeed(sum[:32]),
		ChainCode:  sum[32:],
	}, nil
}

// Derive returns a child key of the receiver using a full path
func (s *PrivateKey) DerivePath(path hdw.Path) (hdw.PrivateKey, error) {
	if k, err := hdw.Derive(s, path); err != nil {
		return nil, err
	} else {
		return k.(hdw.PrivateKey), nil
	}
}

// Chain returns the chain code
func (p *PrivateKey) Chain() []byte {
	return p.ChainCode
}

// Public returns the extended public key corresponding to the receiver
func (p *PrivateKey) ExtendedPublic() hdw.PublicKey {
	return &PublicKey{
		PublicKey: p.Public().(ed25519.PublicKey),
		ChainCode: p.ChainCode,
	}
}

// Naked returns the naked private key that can be used with the standard Go crypto library
func (p *PrivateKey) Naked() crypto.PrivateKey {
	return p.PrivateKey
}

// PublicKey is the extended Ed25519 public key. It implements hdw.PublicKey
type PublicKey struct {
	ed25519.PublicKey
	ChainCode []byte
}

// Chain returns the chain code
func (p *PublicKey) Chain() []byte {
	return p.ChainCode
}

// Naked returns the naked public key that can be used with the standard Go crypto library
func (p *PublicKey) Naked() crypto.PublicKey {
	return p.PublicKey
}

// As SLIP10-Ed25519 doesn't support non hardened derivation this function always returns ErrPublic
func (p *PublicKey) Derive(index uint32) (hdw.PublicKey, error) {
	return nil, ErrPublic
}

// As SLIP10-Ed25519 doesn't support non hardened derivation this function always returns ErrPublic
func (s *PublicKey) DerivePath(path hdw.Path) (hdw.PublicKey, error) {
	return nil, ErrPublic
}

// NewKeyFromSeed generates the root keys from the seed as specified in SLIP-10
func NewKeyFromSeed(seed []byte) *PrivateKey {
	if len(seed) < MinSeedSize || len(seed) > MaxSeedSize {
		panic(fmt.Sprintf("bad seed size %d", len(seed)))
	}

	sum := hmacSha512(seed, []byte(ed25519Key))
	return &PrivateKey{
		PrivateKey: ed25519.NewKeyFromSeed(sum[:32]),
		ChainCode:  sum[32:],
	}
}
