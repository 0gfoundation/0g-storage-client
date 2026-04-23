package core

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECIESDeriveKeyRoundtrip(t *testing.T) {
	recipientPriv, err := crypto.GenerateKey()
	require.NoError(t, err)

	encKey, ephemeralPub, err := DeriveECIESEncryptKey(&recipientPriv.PublicKey)
	require.NoError(t, err)

	decKey, err := DeriveECIESDecryptKey(recipientPriv, ephemeralPub)
	require.NoError(t, err)

	assert.Equal(t, encKey, decKey, "encrypt key and decrypt key should match after ECDH+HKDF")
}

func TestECIESDeriveEncryptKeyFreshEphemeral(t *testing.T) {
	recipientPriv, err := crypto.GenerateKey()
	require.NoError(t, err)

	_, ephA, err := DeriveECIESEncryptKey(&recipientPriv.PublicKey)
	require.NoError(t, err)

	_, ephB, err := DeriveECIESEncryptKey(&recipientPriv.PublicKey)
	require.NoError(t, err)

	assert.NotEqual(t, ephA, ephB, "each call must generate a fresh ephemeral keypair")
}

func TestECIESDeriveDecryptKeyWrongPrivateKeyProducesDifferentKey(t *testing.T) {
	recipientPriv, err := crypto.GenerateKey()
	require.NoError(t, err)
	attackerPriv, err := crypto.GenerateKey()
	require.NoError(t, err)

	encKey, ephemeralPub, err := DeriveECIESEncryptKey(&recipientPriv.PublicKey)
	require.NoError(t, err)

	wrongKey, err := DeriveECIESDecryptKey(attackerPriv, ephemeralPub)
	require.NoError(t, err)

	assert.NotEqual(t, encKey, wrongKey)
}
