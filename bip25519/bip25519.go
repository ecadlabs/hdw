package bip25519

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"filippo.io/edwards25519"
	"github.com/ecadlabs/hdw"
	"github.com/ecadlabs/hdw/bip25519/ex25519"
)

const (
	PrivateKeySize = 64
	MinSeedSize    = 32
)

type PrivateKey struct {
	ex25519.PrivateKey
	ChainCode []byte
}

const ed25519Key = "ed25519 seed"

type Mode int

const (
	ModeDefault Mode = iota
	ModeRetry
	ModeForce
)

type Options struct {
	Mode Mode
	HMAC bool
}

func computeHMAC(data []byte, h func() hash.Hash, key []byte) []byte {
	hmac := hmac.New(h, key)
	hmac.Write(data)
	return hmac.Sum(nil)
}

func newKeyFromSeed(seed []byte, opt *Options) *PrivateKey {
	keyGen := func(data []byte, h func() hash.Hash) []byte {
		var sum hash.Hash
		if opt != nil && opt.HMAC {
			sum = hmac.New(h, []byte(ed25519Key))
		} else {
			sum = h()
		}
		sum.Write(data)
		return sum.Sum(nil)
	}

	h := keyGen(seed, sha512.New)
	switch {
	case opt != nil && opt.Mode == ModeRetry:
		for h[31]&0x20 != 0 {
			h = keyGen(h, sha512.New)
		}
	case opt != nil && opt.Mode == ModeForce:
		h[31] &= 0xdf
	default:
		if h[31]&0x20 != 0 {
			return nil
		}
	}

	h[0] &= 0xf8
	h[31] = (h[31] & 0x7f) | 0x40

	tmp := make([]byte, len(seed)+1)
	tmp[0] = 1
	copy(tmp[1:], seed)
	chain := keyGen(tmp, sha256.New)

	priv, err := ex25519.NewKeyFromBytes(h)
	if err != nil {
		panic(err)
	}
	return &PrivateKey{
		PrivateKey: priv,
		ChainCode:  chain,
	}
}

func NewKeyFromSeed(seed []byte, opt *Options) *PrivateKey {
	if len(seed) < MinSeedSize {
		panic(fmt.Sprintf("bip25519: bad seed size %d", len(seed)))
	}
	return newKeyFromSeed(seed, opt)
}

func mul8(a []byte) {
	var m uint16
	for i := 0; i < len(a); i++ {
		m += uint16(a[i]) << 3
		a[i] = byte(m & 0xff)
		m >>= 8
	}
}

func add(a, b []byte) {
	var m uint16
	for i := 0; i < len(a); i++ {
		m += uint16(a[i]) + uint16(b[i])
		a[i] = byte(m & 0xff)
		m >>= 8
	}
}

func (p *PrivateKey) Derive(index uint32) (hdw.PrivateKey, error) {
	var (
		z []byte
		f []byte
	)

	if index&hdw.Hard != 0 {
		// hardened
		buf := make([]byte, 69)
		copy(buf[1:], p.PrivateKey[:ex25519.ExpandedKeySize])
		binary.LittleEndian.PutUint32(buf[65:], index)
		z = computeHMAC(buf, sha512.New, p.ChainCode)
		buf[0] = 1
		f = computeHMAC(buf, sha512.New, p.ChainCode)
	} else {
		buf := make([]byte, 37)
		buf[0] = 2
		copy(buf[1:], p.PrivateKey[ex25519.ExpandedKeySize:])
		binary.LittleEndian.PutUint32(buf[33:], index)
		z = computeHMAC(buf, sha512.New, p.ChainCode)
		buf[0] = 3
		f = computeHMAC(buf, sha512.New, p.ChainCode)
	}

	var k [64]byte
	copy(k[:], z[:28])
	mul8(k[:32])                   // kl *= 8
	add(k[:32], p.PrivateKey[:32]) // kl += kpl
	copy(k[32:], z[32:])
	add(k[32:], p.PrivateKey[32:]) // kr += kpr

	priv, err := ex25519.NewKeyFromBytes(k[:])
	if err != nil {
		panic(err)
	}
	return &PrivateKey{
		PrivateKey: priv,
		ChainCode:  f[32:],
	}, nil
}

func (p *PrivateKey) Chain() []byte {
	return p.ChainCode
}

func (p *PrivateKey) Naked() crypto.PrivateKey {
	return p.PrivateKey
}

func (p *PrivateKey) bytes() []byte {
	out := make([]byte, 96)
	copy(out, p.PrivateKey)
	copy(out[64:], p.ChainCode)
	return out
}

func keyFromBytes(src []byte) (*PrivateKey, error) {
	if len(src) != 96 {
		return nil, fmt.Errorf("bip25519: bad BIP32-ED25519 private key size %d", len(src))
	}
	out := PrivateKey{
		ChainCode: make([]byte, 32),
	}
	var err error
	out.PrivateKey, err = ex25519.NewKeyFromBytes(src[:64])
	if err != nil {
		panic(err)
	}
	copy(out.ChainCode, src[64:])
	return &out, nil
}

type PublicKey struct {
	ed25519.PublicKey
	ChainCode []byte
}

func (p *PrivateKey) ExtendedPublic() hdw.PublicKey {
	return &PublicKey{
		PublicKey: p.Public().(ed25519.PublicKey),
		ChainCode: p.ChainCode,
	}
}

func (s *PrivateKey) DerivePath(path hdw.Path) (hdw.PrivateKey, error) {
	if k, err := hdw.Derive(s, path); err != nil {
		return nil, err
	} else {
		return k.(hdw.PrivateKey), nil
	}
}

func (p *PublicKey) Chain() []byte {
	return p.ChainCode
}

func (p *PublicKey) Naked() crypto.PublicKey {
	return p.PublicKey
}

func (p *PublicKey) Derive(index uint32) (hdw.PublicKey, error) {
	if index&hdw.Hard != 0 {
		return nil, hdw.ErrHardenedPublic
	}

	buf := make([]byte, 37)
	buf[0] = 2
	copy(buf[1:], p.PublicKey)
	binary.LittleEndian.PutUint32(buf[33:], index)
	z := computeHMAC(buf, sha512.New, p.ChainCode)
	buf[0] = 3
	f := computeHMAC(buf, sha512.New, p.ChainCode)

	var m [32]byte
	copy(m[:], z[:28])
	mul8(m[:]) // m *= 8

	s, err := edwards25519.NewScalar().SetCanonicalBytes(m[:])
	if err != nil {
		panic(err)
	}
	a, err := (&edwards25519.Point{}).SetBytes(p.PublicKey)
	if err != nil {
		panic(err)
	}
	point := (&edwards25519.Point{}).ScalarBaseMult(s)
	point.Add(point, a)

	return &PublicKey{
		PublicKey: point.Bytes(),
		ChainCode: f[32:],
	}, nil
}

func (s *PublicKey) DerivePath(path hdw.Path) (hdw.PublicKey, error) {
	if k, err := hdw.Derive(s, path); err != nil {
		return nil, err
	} else {
		return k.(hdw.PublicKey), nil
	}
}
