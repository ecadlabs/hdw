package hdw

import (
	"crypto"
	"crypto/sha512"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	ChainCodeSize        = 32
	BIP32Hard     uint32 = 1 << 31
)

var ErrHardenedPublic = errors.New("hdw: can't use hardened derivation with public key")

type PrivateKey interface {
	Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
	Chain() []byte
	Derive(index uint32) (PrivateKey, error)
	ExtendedPublic() PublicKey
	Naked() crypto.PrivateKey
}

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
	Chain() []byte
	Derive(index uint32) (PublicKey, error)
	Naked() crypto.PublicKey
}

func NewSeedFromMnemonic(mnemonic string, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}
