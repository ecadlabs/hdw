/*
Package ecdsa deals with [SLIP-10/ECDSA] keys.

[SLIP-10/ECDSA]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
*/

package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ecadlabs/hdw"
)

const (
	secp256k1Key = "Bitcoin seed"
	p256Key      = "Nist256p1 seed"
)

const (
	// MinSeedSize is the minimal allowed seed byte length
	MinSeedSize = 16
	// MaxSeedSize is the maximal allowed seed byte length
	MaxSeedSize = 64
)

func hmacSha512(data []byte, key []byte) []byte {
	hmac := hmac.New(sha512.New, key)
	hmac.Write(data)
	return hmac.Sum(nil)
}

func curveEqual(a, b elliptic.Curve) bool {
	ap := a.Params()
	bp := b.Params()
	return ap.P.Cmp(bp.P) == 0 &&
		ap.N.Cmp(bp.N) == 0 &&
		ap.B.Cmp(bp.B) == 0 &&
		ap.Gx.Cmp(bp.Gx) == 0 &&
		ap.Gy.Cmp(bp.Gy) == 0
}

func curveHMACKey(curve elliptic.Curve) string {
	switch {
	case curveEqual(curve, elliptic.P256()):
		return p256Key
	case curveEqual(curve, secp256k1.S256()):
		return secp256k1Key
	default:
		return ""
	}
}

// PrivateKey is the extended ECDSA private key. It implements hdw.PrivateKey
type PrivateKey struct {
	ecdsa.PrivateKey
	ChainCode []byte
}

// Derive returns a child key of the receiver using a single index
func (p *PrivateKey) Derive(index uint32) (hdw.PrivateKey, error) {
	data := make([]byte, 37)
	if index&hdw.Hard != 0 { // hardened derivation
		copy(data[1:], p.D.Bytes())
	} else {
		copy(data, elliptic.MarshalCompressed(p.Curve, p.X, p.Y))
	}
	binary.BigEndian.PutUint32(data[33:], index)

	var (
		d     *big.Int
		chain []byte
	)
	for {
		sum := hmacSha512(data, p.ChainCode)
		d, chain = new(big.Int).SetBytes(sum[:32]), sum[32:]
		if d.Cmp(p.Params().N) < 0 {
			d.Add(d, p.D)
			d.Mod(d, p.Params().N)
			if d.Sign() != 0 {
				break
			}
		}
		copy(data[1:], chain)
		data[0] = 1
	}

	x, y := p.ScalarBaseMult(d.Bytes())

	return &PrivateKey{
		PrivateKey: ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: p.Curve,
				X:     x,
				Y:     y,
			},
			D: d,
		},
		ChainCode: chain,
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

func (p *PrivateKey) bytes() []byte {
	out := make([]byte, 32)
	d := p.D.Bytes()
	copy(out[32-len(d):], d)
	return out
}

// ExtendedPublic returns the extended public key corresponding to the receiver
func (p *PrivateKey) ExtendedPublic() hdw.PublicKey {
	return &PublicKey{
		PublicKey: p.PublicKey,
		ChainCode: p.ChainCode,
	}
}

// Chain returns the chain code
func (p *PrivateKey) Chain() []byte {
	return p.ChainCode
}

// Naked returns the naked private key that can be used with the standard Go crypto library
func (p *PrivateKey) Naked() crypto.PrivateKey {
	return &p.PrivateKey
}

// PublicKey is the extended ECDSA public key. It implements hdw.PublicKey
type PublicKey struct {
	ecdsa.PublicKey
	ChainCode []byte
}

// Derive returns a child key of the receiver using a single index
func (p *PublicKey) Derive(index uint32) (hdw.PublicKey, error) {
	if index&hdw.Hard != 0 {
		return nil, hdw.ErrHardenedPublic
	}

	data := make([]byte, 37)
	copy(data, elliptic.MarshalCompressed(p.Curve, p.X, p.Y))
	binary.BigEndian.PutUint32(data[33:], index)

	var (
		chain []byte
		x, y  *big.Int
	)
	for {
		var k *big.Int
		sum := hmacSha512(data, p.ChainCode)
		k, chain = new(big.Int).SetBytes(sum[:32]), sum[32:]
		if k.Cmp(p.Params().N) < 0 {
			x, y = p.ScalarBaseMult(k.Bytes())
			x, y = p.Add(x, y, p.X, p.Y)
			if x.Sign() != 0 || y.Sign() != 0 {
				break
			}
		}
		copy(data[1:], chain)
		data[0] = 1
	}

	return &PublicKey{
		PublicKey: ecdsa.PublicKey{
			Curve: p.Curve,
			X:     x,
			Y:     y,
		},
		ChainCode: chain,
	}, nil
}

// Bytes returns the serialized public key data in a compressed form
func (p *PublicKey) Bytes() []byte {
	return elliptic.MarshalCompressed(p.Curve, p.X, p.Y)
}

// Chain returns the chain code
func (p *PublicKey) Chain() []byte {
	return p.ChainCode
}

// Naked returns the naked public key that can be used with the standard Go crypto library
func (p *PublicKey) Naked() crypto.PublicKey {
	return &p.PublicKey
}

// Derive returns a child key of the receiver using a full path
func (s *PublicKey) DerivePath(path hdw.Path) (hdw.PublicKey, error) {
	if k, err := hdw.Derive(s, path); err != nil {
		return nil, err
	} else {
		return k.(hdw.PublicKey), nil
	}
}

// NewKeyFromSeed generates the root key from the seed using a custom HMAC key.
// Can be used with custom curves.
func NewKeyFromSeedWithHMACKey(seed []byte, curve elliptic.Curve, key string) *PrivateKey {
	if len(seed) < MinSeedSize || len(seed) > MaxSeedSize {
		panic(fmt.Sprintf("ecdsa: bad seed size %d", len(seed)))
	}

	if curve.Params().BitSize != 256 {
		panic(fmt.Sprintf("ecdsa: invalid curve bit size %d", curve.Params().BitSize))
	}
	var (
		d     *big.Int
		chain []byte
	)
	for {
		sum := hmacSha512(seed, []byte(key))
		d, chain = new(big.Int).SetBytes(sum[:32]), sum[32:]
		if len(d.Bits()) == 0 || d.Cmp(curve.Params().N) >= 0 {
			seed = sum
		} else {
			break
		}
	}

	x, y := curve.ScalarBaseMult(d.Bytes())
	return &PrivateKey{
		PrivateKey: ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			D: d,
		},
		ChainCode: chain,
	}
}

// NewKeyFromSeed generates the root key from the seed as specified in SLIP-10
func NewKeyFromSeed(seed []byte, curve elliptic.Curve) (*PrivateKey, error) {
	key := curveHMACKey(curve)
	if key == "" {
		return nil, fmt.Errorf("ecdsa: unknown curve %s", curve.Params().Name)
	}
	return NewKeyFromSeedWithHMACKey(seed, curve, key), nil
}
