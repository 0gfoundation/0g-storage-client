package transfer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
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
// regular indexer-based download when the file is not available in hot storage.
type HotDownloader struct {
	routerClient *node.HotRouterClient
	privateKey   *ecdsa.PrivateKey
	fallback     IDownloader

	encryptionKey []byte

	logger *logrus.Logger
}

// NewHotDownloader creates a new HotDownloader.
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

// Download downloads a single file, trying hot storage first and falling back to regular download.
func (d *HotDownloader) Download(ctx context.Context, root, filename string, withProof bool) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}

	ok, hotErr := d.tryHotDownload(ctx, root, outFile)
	outFile.Close()

	if !ok {
		os.Remove(filename)
		if hotErr != nil {
			d.logger.WithError(hotErr).Warn("Hot storage download failed, falling back to regular download")
		} else {
			d.logger.Info("File not in hot storage, falling back to regular download")
		}
		return d.fallback.Download(ctx, root, filename, withProof)
	}

	if len(d.encryptionKey) > 0 {
		if err := d.decryptFile(filename); err != nil {
			return errors.WithMessage(err, "failed to decrypt hot storage data")
		}
	}

	d.logger.Info("Completed download from hot storage")
	return nil
}

// DownloadFragments downloads multiple fragments, trying hot storage first per fragment.
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
		tempFile := fmt.Sprintf("%v.temp", root)

		ok, hotErr := d.tryHotDownloadToFile(ctx, root, tempFile)
		if !ok {
			if hotErr != nil {
				d.logger.WithError(hotErr).WithField("fragment", i).Warn("Hot storage failed for fragment, falling back")
			} else {
				d.logger.WithField("fragment", i).Info("Fragment not in hot storage, falling back")
			}
			if err := d.fallback.Download(ctx, root, tempFile, withProof); err != nil {
				return errors.WithMessage(err, fmt.Sprintf("failed to download fragment %d", i))
			}
		}

		inFile, err := os.Open(tempFile)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to open temp file for fragment %d", i))
		}
		_, err = io.Copy(outFile, inFile)
		inFile.Close()
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to copy fragment %d", i))
		}
		os.Remove(tempFile)
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
// Used only by the encrypted fragments path where bytes are needed for decryption.
func (d *HotDownloader) downloadFragmentData(ctx context.Context, root string, index int, withProof bool) ([]byte, error) {
	var buf bytes.Buffer
	ok, err := d.tryHotDownload(ctx, root, &buf)
	if !ok {
		if err != nil {
			d.logger.WithError(err).WithField("fragment", index).Warn("Hot storage failed for fragment, falling back")
		} else {
			d.logger.WithField("fragment", index).Info("Fragment not in hot storage, falling back")
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
	return buf.Bytes(), nil
}

// tryHotDownload streams hot storage data for root into w.
// Returns (true, nil) on cache hit, (false, nil) on cache miss, (false, err) on error.
func (d *HotDownloader) tryHotDownload(ctx context.Context, root string, w io.Writer) (bool, error) {
	d.logger.WithField("root", root).Info("Attempting hot storage download")

	auth, err := d.routerClient.GetDownloadAuth(ctx, d.privateKey, []string{root})
	if err != nil {
		return false, fmt.Errorf("failed to get download auth from router: %w", err)
	}
	if auth == nil {
		d.logger.WithField("root", root).Info("File not available in hot storage")
		return false, nil
	}
	d.logger.WithFields(logrus.Fields{
		"root":     root,
		"node_url": auth.NodeURL,
		"provider": auth.Provider,
	}).Info("Got download auth from router")

	hotClient, err := node.NewHotClient(auth.NodeURL)
	if err != nil {
		return false, fmt.Errorf("failed to connect to hot storage node %s: %w", auth.NodeURL, err)
	}
	defer hotClient.Close()

	userAddr := crypto.PubkeyToAddress(d.privateKey.PublicKey)
	if err := hotClient.HotDownload(ctx, userAddr.Hex(), auth, root, w); err != nil {
		return false, fmt.Errorf("hot download failed: %w", err)
	}

	d.logger.WithField("root", root).Info("Hot storage downloaded successfully")
	return true, nil
}

// tryHotDownloadToFile streams hot storage data into a new file at path.
// Returns (true, nil) on success, (false, nil/err) on miss/error — partial file is removed on failure.
func (d *HotDownloader) tryHotDownloadToFile(ctx context.Context, root, path string) (bool, error) {
	f, err := os.Create(path)
	if err != nil {
		return false, fmt.Errorf("failed to create temp file: %w", err)
	}

	ok, err := d.tryHotDownload(ctx, root, f)
	f.Close()
	if !ok {
		os.Remove(path)
	}
	return ok, err
}

// decryptFile decrypts the file at filename in-place using the downloader's encryption key.
func (d *HotDownloader) decryptFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to read file for decryption")
	}
	var key [32]byte
	copy(key[:], d.encryptionKey)
	decrypted, err := core.DecryptFile(&key, data)
	if err != nil {
		return errors.WithMessage(err, "failed to decrypt file")
	}
	return errors.WithMessage(os.WriteFile(filename, decrypted, 0644), "failed to write decrypted file")
}
