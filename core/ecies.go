package core

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/hkdf"
)

// EphemeralPubKeySize is the size of a compressed secp256k1 public key (33 bytes).
const EphemeralPubKeySize = 33

// eciesHKDFInfo binds the derived key to this protocol so the same ECDH secret
// used elsewhere won't collide with our AES key derivation.
var eciesHKDFInfo = []byte("0g-storage-client/ecies/v1/aes-256")

// DeriveECIESEncryptKey generates a fresh ephemeral secp256k1 keypair, performs ECDH with
// recipientPub, runs the shared secret through HKDF-SHA256, and returns a 32-byte AES key
// plus the compressed ephemeral public key (to be stored in the file header).
func DeriveECIESEncryptKey(recipientPub *ecdsa.PublicKey) (key [32]byte, ephemeralPub [EphemeralPubKeySize]byte, err error) {
	ephemeralPriv, err := crypto.GenerateKey()
	if err != nil {
		return key, ephemeralPub, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	shared, err := eciesShared(ephemeralPriv, recipientPub)
	if err != nil {
		return key, ephemeralPub, err
	}

	if err := hkdfExpand(shared, key[:]); err != nil {
		return key, ephemeralPub, err
	}

	copy(ephemeralPub[:], crypto.CompressPubkey(&ephemeralPriv.PublicKey))
	return key, ephemeralPub, nil
}

// DeriveECIESDecryptKey recovers the AES key from the recipient's private key and the
// compressed ephemeral public key stored in the file header.
func DeriveECIESDecryptKey(recipientPriv *ecdsa.PrivateKey, ephemeralPub [EphemeralPubKeySize]byte) (key [32]byte, err error) {
	pub, err := crypto.DecompressPubkey(ephemeralPub[:])
	if err != nil {
		return key, fmt.Errorf("failed to decompress ephemeral pubkey: %w", err)
	}

	shared, err := eciesShared(recipientPriv, pub)
	if err != nil {
		return key, err
	}

	if err := hkdfExpand(shared, key[:]); err != nil {
		return key, err
	}
	return key, nil
}

// eciesShared runs the ECDH step via go-ethereum's ecies package, returning the raw
// 32-byte shared secret (x-coordinate of the shared point).
func eciesShared(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	eciesPriv := ecies.ImportECDSA(priv)
	eciesPub := ecies.ImportECDSAPublic(pub)
	shared, err := eciesPriv.GenerateShared(eciesPub, 32, 0)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}
	return shared, nil
}

// hkdfExpand runs HKDF-SHA256 over the shared secret and fills out with derived bytes.
func hkdfExpand(shared, out []byte) error {
	reader := hkdf.New(sha256.New, shared, nil, eciesHKDFInfo)
	if _, err := io.ReadFull(reader, out); err != nil {
		return fmt.Errorf("hkdf expand failed: %w", err)
	}
	return nil
}
