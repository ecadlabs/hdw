/*
Package hdw provides a unified API for dealing with hierarchical deterministic keys
also known as hierarchical deterministic wallets in application to blockchains as defined in BIP-32 and SLIP-10
*/
package hdw

import (
	"crypto"
	"crypto/sha512"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ChainCodeSize is the length of chain code common for all key types
const ChainCodeSize = 32

// Hard is the flag signifying so called hardened derivation if added to the derivation index.
// The exact use of it is specific to the chosen algorithm but in general it means that the private key is used
// to build the hash chain
const Hard uint32 = 1 << 31

// ErrHardenedPublic returned if an attempt to use hardened derivation with a public key was made
var ErrHardenedPublic = errors.New("hdw: can't use hardened derivation with public key")

// PrivateKey is an extended private key bearing the chain code required for derivation of child keys
type PrivateKey interface {
	crypto.Signer
	// Equal reports whether receiver and x have the same value
	Equal(x crypto.PrivateKey) bool
	// Chain returns the chain code
	Chain() []byte
	// Derive returns a child key of the receiver using a single index
	Derive(index uint32) (PrivateKey, error)
	// Derive returns a child key of the receiver using a full path
	DerivePath(path Path) (PrivateKey, error)
	// Public returns the extended public key corresponding to the receiver
	ExtendedPublic() PublicKey
	// Naked returns the naked private key that can be used with the standard Go crypto library
	Naked() crypto.PrivateKey
}

// PrivateKey is an extended public key bearing the chain code required for derivation of child keys
type PublicKey interface {
	// Equal reports whether receiver and x have the same value
	Equal(x crypto.PublicKey) bool
	// Chain returns the chain code
	Chain() []byte
	// Derive returns a child key of the receiver using single index
	Derive(index uint32) (PublicKey, error)
	// Derive returns a child key of the receiver using a full path
	DerivePath(path Path) (PublicKey, error)
	// Naked returns the naked public key that can be used with the standard Go crypto library
	Naked() crypto.PublicKey
}

// NewSeedFromMnemonic generates the seed value from the mnemonic as specified in BIP-39.
// The seed is the primary secret used to derive root keys and their derivatives
func NewSeedFromMnemonic(mnemonic string, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}

// Path is a BIP-32/SLIP-10 derivation path
type Path []uint32

// HasPrefix reports whether receiver has a given prefix
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

// String formats the path to the BIP-32/SLIP-10 textual form
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

// ParsePath parses s as a BIP-32/SLIP-10 path, like "m/1'/2"
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

// Derive returns a child key of root using a full path. root must be either PrivateKey or PublicKey
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
