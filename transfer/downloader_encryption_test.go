package transfer

import (
	"testing"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveDecryptionKeySymmetricV1(t *testing.T) {
	header, err := core.NewEncryptionHeader()
	require.NoError(t, err)

	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = 0x42
	}

	got, err := ResolveDecryptionKey(keyBytes, nil, header)
	require.NoError(t, err)
	var want [32]byte
	copy(want[:], keyBytes)
	assert.Equal(t, want, got)
}

func TestResolveDecryptionKeyV1RequiresSymmetricKey(t *testing.T) {
	header, err := core.NewEncryptionHeader()
	require.NoError(t, err)

	priv, err := crypto.GenerateKey()
	require.NoError(t, err)

	_, err = ResolveDecryptionKey(nil, priv, header)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "v1")
}

func TestResolveDecryptionKeyECIESv2(t *testing.T) {
	priv, err := crypto.GenerateKey()
	require.NoError(t, err)

	header, aesKey, err := core.NewECIESEncryptionHeader(&priv.PublicKey)
	require.NoError(t, err)

	got, err := ResolveDecryptionKey(nil, priv, header)
	require.NoError(t, err)
	assert.Equal(t, aesKey, got, "derived key must match upload-side key")
}

func TestResolveDecryptionKeyV2RequiresPrivateKey(t *testing.T) {
	priv, err := crypto.GenerateKey()
	require.NoError(t, err)

	header, _, err := core.NewECIESEncryptionHeader(&priv.PublicKey)
	require.NoError(t, err)

	_, err = ResolveDecryptionKey(make([]byte, 32), nil, header)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "v2")
}

func TestResolveDecryptionKeyInvalidSymmetricKeyLength(t *testing.T) {
	header, err := core.NewEncryptionHeader()
	require.NoError(t, err)

	_, err = ResolveDecryptionKey(make([]byte, 16), nil, header)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}
