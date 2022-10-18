package hdw

import (
	"crypto"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	ChainCodeSize        = 32
	Hard          uint32 = 1 << 31
)

var ErrHardenedPublic = errors.New("hdw: can't use hardened derivation with public key")

type PrivateKey interface {
	Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
	Chain() []byte
	Derive(index uint32) (PrivateKey, error)
	DerivePath(path Path) (PrivateKey, error)
	ExtendedPublic() PublicKey
	Naked() crypto.PrivateKey
}

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
	Chain() []byte
	Derive(index uint32) (PublicKey, error)
	DerivePath(path Path) (PublicKey, error)
	Naked() crypto.PublicKey
}

func NewSeedFromMnemonic(mnemonic string, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}

type Path []uint32

func (p Path) HasPrefix(prefix Path) bool {
	if len(prefix) > len(p) {
		return false
	}
	for i, x := range prefix {
		if x != p[i] {
			return false
		}
	}
	return true
}

func (path Path) String() string {
	var out strings.Builder
	out.WriteByte('m')
	for _, x := range path {
		out.WriteByte('/')
		out.WriteString(strconv.FormatUint(uint64(x&^Hard), 10))
		if x&Hard != 0 {
			out.WriteByte('\'')
		}
	}
	return out.String()
}

func ParsePath(s string) (Path, error) {
	if len(s) == 0 {
		return Path{}, nil
	}
	parts := strings.Split(s, "/")
	out := make(Path, 0, len(parts))
	if parts[0] == "m" {
		parts = parts[1:]
	}
	for _, p := range parts {
		if len(p) == 0 {
			return nil, fmt.Errorf("hdw: invalid BIP32 path: %s", s)
		}
		h := uint32(0)
		if p[len(p)-1] == '\'' || p[len(p)-1] == 'h' || p[len(p)-1] == 'H' {
			h = Hard
			p = p[:len(p)-1]
		}
		index, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("hdw: %w", err)
		}
		out = append(out, uint32(index)|h)
	}
	return out, nil
}

func Derive(root any, path Path) (any, error) {
	switch k := root.(type) {
	case PrivateKey:
		for _, x := range path {
			var err error
			k, err = k.Derive(x)
			if err != nil {
				return nil, err
			}
		}
		return k, nil
	case PublicKey:
		for _, x := range path {
			var err error
			k, err = k.Derive(x)
			if err != nil {
				return nil, err
			}
		}
		return k, nil
	default:
		return nil, fmt.Errorf("hdw: %T is not a key", k)
	}
}
