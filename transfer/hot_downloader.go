package transfer

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"os"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var _ IDownloader = (*HotDownloader)(nil)

// HotDownloader downloads files from the hot storage network, falling back to
// regular indexer-based download on cache miss.
type HotDownloader struct {
	routerClient *node.HotRouterClient
	privateKey   *ecdsa.PrivateKey
	fallback     IDownloader

	encryptionKey []byte

	logger *logrus.Logger
}

// NewHotDownloader creates a new HotDownloader.
// routerClient is the hot storage router client.
// privateKey is the user's private key for signing download requests.
// fallback is the regular downloader to use when the file is not cached in hot storage.
func NewHotDownloader(routerClient *node.HotRouterClient, privateKey *ecdsa.PrivateKey, fallback IDownloader, opts ...zg_common.LogOption) *HotDownloader {
	return &HotDownloader{
		routerClient: routerClient,
		privateKey:   privateKey,
		fallback:     fallback,
		logger:       zg_common.NewLogger(opts...),
	}
}

// WithEncryptionKey sets the encryption key for post-download decryption.
func (d *HotDownloader) WithEncryptionKey(key []byte) *HotDownloader {
	d.encryptionKey = key
	return d
}

// Download downloads a single file from hot storage, falling back to regular download on cache miss.
func (d *HotDownloader) Download(ctx context.Context, root, filename string, withProof bool) error {
	data, err := d.tryHotDownload(ctx, root)
	if err != nil {
		d.logger.WithError(err).Warn("Hot storage download failed, falling back to regular download")
		return d.fallback.Download(ctx, root, filename, withProof)
	}

	if data == nil {
		d.logger.Info("File not cached in hot storage, falling back to regular download")
		return d.fallback.Download(ctx, root, filename, withProof)
	}

	// Decrypt if encryption key is set.
	if len(d.encryptionKey) > 0 {
		var key [32]byte
		copy(key[:], d.encryptionKey)
		data, err = core.DecryptFile(&key, data)
		if err != nil {
			return errors.WithMessage(err, "failed to decrypt hot storage data")
		}
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return errors.WithMessage(err, "failed to write downloaded file")
	}

	d.logger.Info("Completed download from hot storage")
	return nil
}

// DownloadFragments downloads multiple fragments from hot storage, falling back per-fragment.
func (d *HotDownloader) DownloadFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	if len(d.encryptionKey) > 0 {
		return d.downloadEncryptedFragments(ctx, roots, filename, withProof)
	}
	return d.downloadPlainFragments(ctx, roots, filename, withProof)
}

func (d *HotDownloader) downloadPlainFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}
	defer outFile.Close()

	for i, root := range roots {
		data, err := d.downloadFragmentData(ctx, root, i, withProof)
		if err != nil {
			return err
		}

		if _, err := outFile.Write(data); err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to write fragment %d", i))
		}
	}

	return nil
}

func (d *HotDownloader) downloadEncryptedFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	if len(d.encryptionKey) != 32 {
		return errors.New("encryption key must be 32 bytes")
	}
	var key [32]byte
	copy(key[:], d.encryptionKey)

	outFile, err := os.Create(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}
	defer outFile.Close()

	var header *core.EncryptionHeader
	var cumulativeDataOffset uint64

	for i, root := range roots {
		fragmentData, err := d.downloadFragmentData(ctx, root, i, withProof)
		if err != nil {
			return err
		}

		if i == 0 {
			header, err = core.ParseEncryptionHeader(fragmentData)
			if err != nil {
				return errors.WithMessage(err, "failed to parse encryption header from fragment 0")
			}
		}

		plaintext, newOffset, err := core.DecryptFragmentData(&key, header, fragmentData, i == 0, cumulativeDataOffset)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to decrypt fragment %d", i))
		}
		cumulativeDataOffset = newOffset

		if _, err := outFile.Write(plaintext); err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to write decrypted fragment %d", i))
		}
	}

	d.logger.Info("Succeeded to decrypt and concatenate encrypted fragments from hot storage")
	return nil
}

// downloadFragmentData gets the raw bytes for a single fragment, trying hot storage first.
func (d *HotDownloader) downloadFragmentData(ctx context.Context, root string, index int, withProof bool) ([]byte, error) {
	data, err := d.tryHotDownload(ctx, root)
	if err != nil || data == nil {
		if err != nil {
			d.logger.WithError(err).WithField("fragment", index).Warn("Hot storage failed for fragment, falling back")
		} else {
			d.logger.WithField("fragment", index).Info("Fragment not cached in hot storage, falling back")
		}
		tempFile := fmt.Sprintf("%v.temp", root)
		if err := d.fallback.Download(ctx, root, tempFile, withProof); err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("failed to download fragment %d", index))
		}
		fragmentData, err := os.ReadFile(tempFile)
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("failed to read fragment %d", index))
		}
		os.Remove(tempFile)
		return fragmentData, nil
	}
	return data, nil
}

// tryHotDownload attempts to download a file from hot storage.
// Returns (data, nil) on cache hit, (nil, nil) on cache miss, or (nil, err) on failure.
func (d *HotDownloader) tryHotDownload(ctx context.Context, root string) ([]byte, error) {
	d.logger.WithField("root", root).Info("Attempting hot storage download")

	// Step 1: Ask router which hot node has the file.
	auth, err := d.routerClient.GetDownloadAuth(ctx, d.privateKey, root)
	if err != nil {
		return nil, fmt.Errorf("failed to get download auth from router: %w", err)
	}
	if auth == nil {
		// Router returned 404 — no hot node has the file cached.
		d.logger.WithField("root", root).Info("File not available in hot storage")
		return nil, nil
	}
	d.logger.WithFields(logrus.Fields{
		"root":     root,
		"node_url": auth.NodeURL,
		"provider": auth.Provider,
	}).Info("Got download auth from router")

	// Step 2: Download from the assigned hot node.
	hotClient, err := node.NewHotClient(auth.NodeURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to hot storage node %s: %w", auth.NodeURL, err)
	}
	defer hotClient.Close()

	userAddr := crypto.PubkeyToAddress(d.privateKey.PublicKey)
	resp, err := hotClient.HotDownload(ctx, userAddr.Hex(), auth)
	if err != nil {
		return nil, fmt.Errorf("hot_download RPC failed: %w", err)
	}

	// Decode base64 data.
	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %w", err)
	}

	d.logger.WithFields(logrus.Fields{
		"root": root,
		"size": len(data),
	}).Info("Hot storage cache hit, downloaded successfully")

	return data, nil
}
