package transfer

import (
	"testing"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapEncryptionNoKeyPassthrough(t *testing.T) {
	uploader := &Uploader{logger: logrus.New()}
	data, err := core.NewDataInMemory([]byte("hello"))
	require.NoError(t, err)

	wrapped, err := uploader.wrapEncryption(data, UploadOption{})
	require.NoError(t, err)
	assert.Same(t, core.IterableData(data), wrapped, "no key means pass-through")
}

func TestWrapEncryptionSymmetric(t *testing.T) {
	uploader := &Uploader{logger: logrus.New()}
	data, err := core.NewDataInMemory([]byte("hello"))
	require.NoError(t, err)
	key := make([]byte, 32)

	wrapped, err := uploader.wrapEncryption(data, UploadOption{EncryptionKey: key})
	require.NoError(t, err)
	_, ok := wrapped.(*core.EncryptedData)
	assert.True(t, ok, "symmetric key should produce EncryptedData")
	assert.Equal(t, data.Size()+int64(core.SymmetricHeaderSize), wrapped.Size())
}

func TestWrapEncryptionECIES(t *testing.T) {
	uploader := &Uploader{logger: logrus.New()}
	data, err := core.NewDataInMemory([]byte("hello"))
	require.NoError(t, err)

	priv, err := crypto.GenerateKey()
	require.NoError(t, err)

	wrapped, err := uploader.wrapEncryption(data, UploadOption{RecipientPubKey: &priv.PublicKey})
	require.NoError(t, err)
	encData, ok := wrapped.(*core.EncryptedData)
	require.True(t, ok)
	assert.Equal(t, uint8(core.ECIESVersion), encData.Header().Version)
	assert.Equal(t, data.Size()+int64(core.ECIESHeaderSize), wrapped.Size())
}

func TestWrapEncryptionMutuallyExclusive(t *testing.T) {
	uploader := &Uploader{logger: logrus.New()}
	data, err := core.NewDataInMemory([]byte("hello"))
	require.NoError(t, err)

	priv, err := crypto.GenerateKey()
	require.NoError(t, err)

	_, err = uploader.wrapEncryption(data, UploadOption{
		EncryptionKey:   make([]byte, 32),
		RecipientPubKey: &priv.PublicKey,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}
