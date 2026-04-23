package transfer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"os"
	"runtime"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer/download"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// ResolveDecryptionKey picks the correct AES key for the given header version.
// v1 headers require a 32-byte symmetric key; v2 headers require a wallet private key
// and derive the AES key from it and the header's ephemeral pubkey.
func ResolveDecryptionKey(symmetricKey []byte, walletPriv *ecdsa.PrivateKey, header *core.EncryptionHeader) ([32]byte, error) {
	var key [32]byte
	switch header.Version {
	case core.SymmetricVersion:
		if len(symmetricKey) == 0 {
			return key, errors.New("v1 encrypted file requires --encryption-key")
		}
		if len(symmetricKey) != 32 {
			return key, errors.New("encryption key must be 32 bytes")
		}
		copy(key[:], symmetricKey)
		return key, nil
	case core.ECIESVersion:
		if walletPriv == nil {
			return key, errors.New("v2 encrypted file requires --private-key for ECIES decryption")
		}
		return core.DeriveECIESDecryptKey(walletPriv, header.EphemeralPub)
	default:
		return key, errors.Errorf("unsupported encryption version: %d", header.Version)
	}
}

var (
	_ IDownloader = (*Downloader)(nil)

	ErrFileAlreadyExists = errors.New("File already exists")
)

type IDownloader interface {
	Download(ctx context.Context, root, filename string, withProof bool) error
	DownloadFragments(ctx context.Context, roots []string, filename string, withProof bool) error
}

// Downloader downloader to download file to storage nodes
type Downloader struct {
	clients []*node.ZgsClient

	routines int

	encryptionKey    []byte            // optional 32-byte AES-256 decryption key (v1 symmetric)
	walletPrivateKey *ecdsa.PrivateKey // optional wallet private key for ECIES v2 decryption

	logger *logrus.Logger
}

// NewDownloader Initialize a new downloader.
func NewDownloader(clients []*node.ZgsClient, opts ...zg_common.LogOption) (*Downloader, error) {
	if len(clients) == 0 {
		return nil, errors.New("storage node not specified")
	}
	downloader := &Downloader{
		clients: clients,
		logger:  zg_common.NewLogger(opts...),
	}
	downloader.routines = runtime.GOMAXPROCS(0)
	return downloader, nil
}

func (downloader *Downloader) WithRoutines(routines int) *Downloader {
	downloader.routines = routines
	return downloader
}

// WithEncryptionKey sets the v1 symmetric encryption key for post-download decryption.
// The key must be exactly 32 bytes (AES-256).
func (downloader *Downloader) WithEncryptionKey(key []byte) *Downloader {
	downloader.encryptionKey = key
	return downloader
}

// WithWalletPrivateKey sets the wallet private key used to decrypt v2 (ECIES) encrypted files.
func (downloader *Downloader) WithWalletPrivateKey(priv *ecdsa.PrivateKey) *Downloader {
	downloader.walletPrivateKey = priv
	return downloader
}

// hasDecryptionKey reports whether this downloader can attempt to decrypt an encrypted file.
func (downloader *Downloader) hasDecryptionKey() bool {
	return len(downloader.encryptionKey) > 0 || downloader.walletPrivateKey != nil
}

func (downloader *Downloader) DownloadFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	if downloader.hasDecryptionKey() {
		return downloader.downloadEncryptedFragments(ctx, roots, filename, withProof)
	}
	return downloader.downloadPlainFragments(ctx, roots, filename, withProof)
}

func (downloader *Downloader) downloadPlainFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}
	defer outFile.Close()

	for _, root := range roots {
		tempFile := fmt.Sprintf("%v.temp", root)
		err := downloader.Download(ctx, root, tempFile, withProof)
		if err != nil {
			return errors.WithMessage(err, "Failed to download file")
		}
		inFile, err := os.Open(tempFile)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to open file %s", tempFile))
		}
		_, err = io.Copy(outFile, inFile)
		inFile.Close()
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to copy content from temp file %s", tempFile))
		}

		err = os.Remove(tempFile)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to delete temp file %s:", tempFile))
		}
	}

	return nil
}

// downloadEncryptedFragments downloads fragments raw (without decryption),
// extracts the encryption header from fragment 0, then decrypts each fragment
// with proper CTR offset tracking and writes decrypted data to the output file.
func (downloader *Downloader) downloadEncryptedFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}
	defer outFile.Close()

	var header *core.EncryptionHeader
	var key [32]byte
	var cumulativeDataOffset uint64

	for i, root := range roots {
		tempFile := fmt.Sprintf("%v.temp", root)

		// Download raw (without decryption)
		if err := downloader.downloadAndValidate(ctx, root, tempFile, withProof); err != nil {
			return errors.WithMessage(err, fmt.Sprintf("Failed to download fragment %d", i))
		}

		fragmentData, err := os.ReadFile(tempFile)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to read fragment %d", i))
		}
		os.Remove(tempFile)

		if i == 0 {
			// First fragment: extract header and resolve the AES key from available material.
			header, err = core.ParseEncryptionHeader(fragmentData)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse encryption header from fragment 0")
			}
			key, err = ResolveDecryptionKey(downloader.encryptionKey, downloader.walletPrivateKey, header)
			if err != nil {
				return err
			}
		}

		plaintext, newOffset, err := core.DecryptFragmentData(&key, header, fragmentData, i == 0, cumulativeDataOffset)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("Failed to decrypt fragment %d", i))
		}
		cumulativeDataOffset = newOffset

		if _, err := outFile.Write(plaintext); err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to write decrypted fragment %d", i))
		}
	}

	downloader.logger.Info("Succeeded to decrypt and concatenate encrypted fragments")
	return nil
}

// downloadAndValidate downloads and validates a file without decryption.
func (downloader *Downloader) downloadAndValidate(ctx context.Context, root, filename string, withProof bool) error {
	hash := common.HexToHash(root)

	info, err := downloader.queryFile(ctx, hash)
	if err != nil {
		return errors.WithMessage(err, "Failed to query file info")
	}

	if err = downloader.checkExistence(filename, hash); err != nil {
		return errors.WithMessage(err, "Failed to check file existence")
	}

	if err = downloader.downloadFile(ctx, filename, hash, info, withProof); err != nil {
		return errors.WithMessage(err, "Failed to download file")
	}

	if err = downloader.validateDownloadFile(root, filename, int64(info.Tx.Size)); err != nil {
		return errors.WithMessage(err, "Failed to validate downloaded file")
	}

	return nil
}

// Download download data from storage nodes.
func (downloader *Downloader) Download(ctx context.Context, root, filename string, withProof bool) error {
	if err := downloader.downloadAndValidate(ctx, root, filename, withProof); err != nil {
		return err
	}

	// Decrypt the file if any decryption key is set
	if downloader.hasDecryptionKey() {
		if err := downloader.decryptDownloadedFile(filename); err != nil {
			return errors.WithMessage(err, "Failed to decrypt downloaded file")
		}
	}

	return nil
}

func (downloader *Downloader) queryFile(ctx context.Context, root common.Hash) (info *node.FileInfo, err error) {
	// do not require file finalized
	for _, v := range downloader.clients {
		info, err = v.GetFileInfo(ctx, root, true)
		if err != nil {
			return nil, err
		}

		if info == nil {
			return nil, fmt.Errorf("file not found on node %v", v.URL())
		}
	}

	downloader.logger.WithField("file", info).Debug("File found by root hash")

	return
}

func (downloader *Downloader) checkExistence(filename string, hash common.Hash) error {
	file, err := core.Open(filename)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return errors.WithMessage(err, "Failed to open file")
	}

	defer file.Close()

	tree, err := core.MerkleTree(file)
	if err != nil {
		return errors.WithMessage(err, "Failed to create file merkle tree")
	}

	if tree.Root().Hex() == hash.Hex() {
		return ErrFileAlreadyExists
	}

	return errors.New("File already exists with different hash")
}

func (downloader *Downloader) downloadFile(ctx context.Context, filename string, root common.Hash, info *node.FileInfo, withProof bool) error {
	file, err := download.CreateDownloadingFile(filename, root, int64(info.Tx.Size))
	if err != nil {
		return errors.WithMessage(err, "Failed to create downloading file")
	}
	defer file.Close()

	downloader.logger.WithField("num nodes", len(downloader.clients)).Info("Begin to download file from storage nodes")

	sd, err := newSegmentDownloader(downloader, info, file, withProof)
	if err != nil {
		return errors.WithMessage(err, "Failed to create segment downloader")
	}

	if err = sd.Download(ctx); err != nil {
		return errors.WithMessage(err, "Failed to download file")
	}

	if err := file.Seal(); err != nil {
		return errors.WithMessage(err, "Failed to seal downloading file")
	}

	downloader.logger.Info("Completed to download file")

	return nil
}

func (downloader *Downloader) validateDownloadFile(root, filename string, fileSize int64) error {
	file, err := core.Open(filename)
	if err != nil {
		return errors.WithMessage(err, "Failed to open file")
	}
	defer file.Close()

	if file.Size() != fileSize {
		return errors.Errorf("File size mismatch: expected = %v, downloaded = %v", fileSize, file.Size())
	}

	tree, err := core.MerkleTree(file)
	if err != nil {
		return errors.WithMessage(err, "Failed to create merkle tree")
	}

	if rootHex := tree.Root().Hex(); rootHex != root {
		return errors.Errorf("Merkle root mismatch, downloaded = %v", rootHex)
	}

	downloader.logger.Info("Succeeded to validate the downloaded file")

	return nil
}

func (downloader *Downloader) decryptDownloadedFile(filename string) error {
	encrypted, err := os.ReadFile(filename)
	if err != nil {
		return errors.WithMessage(err, "Failed to read encrypted file")
	}

	header, err := core.ParseEncryptionHeader(encrypted)
	if err != nil {
		return errors.WithMessage(err, "Failed to parse encryption header")
	}

	key, err := ResolveDecryptionKey(downloader.encryptionKey, downloader.walletPrivateKey, header)
	if err != nil {
		return err
	}

	decrypted, err := core.DecryptFile(&key, encrypted)
	if err != nil {
		return errors.WithMessage(err, "Failed to decrypt file")
	}

	if err := os.WriteFile(filename, decrypted, 0644); err != nil {
		return errors.WithMessage(err, "Failed to write decrypted file")
	}

	downloader.logger.Info("Succeeded to decrypt the downloaded file")

	return nil
}
