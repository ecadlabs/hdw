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
	MinSeedSize = 16
	MaxSeedSize = 64
)

var (
	ErrNonHardened = errors.New("ed25519: non hardened derivation")
	ErrPublic      = errors.New("ed25519: can't use public key for derivation")
)

type PrivateKey struct {
	ed25519.PrivateKey
	ChainCode []byte
}

func hmacSha512(data []byte, key []byte) []byte {
	hmac := hmac.New(sha512.New, key)
	hmac.Write(data)
	return hmac.Sum(nil)
}

func (s *PrivateKey) Derive(index uint32) (hdw.PrivateKey, error) {
	data := make([]byte, 37)
	if index&hdw.BIP32Hard == 0 {
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

func (p *PrivateKey) Chain() []byte {
	return p.ChainCode
}

func (p *PrivateKey) ExtendedPublic() hdw.PublicKey {
	return &PublicKey{
		PublicKey: p.Public().(ed25519.PublicKey),
		ChainCode: p.ChainCode,
	}
}

func (p *PrivateKey) Naked() crypto.PrivateKey {
	return p.PrivateKey
}

type PublicKey struct {
	ed25519.PublicKey
	ChainCode []byte
}

func (p *PublicKey) Chain() []byte {
	return p.ChainCode
}

func (p *PublicKey) Naked() crypto.PublicKey {
	return p.PublicKey
}

func (p *PublicKey) Derive(index uint32) (hdw.PublicKey, error) {
	return nil, ErrPublic
}

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
