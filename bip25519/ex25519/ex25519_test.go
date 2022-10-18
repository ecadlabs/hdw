package ex25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEx25519Derive(t *testing.T) {
	buf := make([]byte, ExpandedKeySize)
	_, err := io.ReadFull(rand.Reader, buf)
	require.NoError(t, err)

	pk, err := NewKeyFromBytes(buf)
	require.NoError(t, err)

	msg := []byte{'t', 'e', 's', 't'}
	s := Sign(pk, msg)

	pub := pk.Public()
	assert.True(t, ed25519.Verify(pub.(ed25519.PublicKey), msg, s))
}
