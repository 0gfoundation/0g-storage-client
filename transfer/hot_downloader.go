package transfer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"os"
	"path/filepath"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/common"
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

	encryptionKey    []byte            // v1 symmetric AES-256 key
	walletPrivateKey *ecdsa.PrivateKey // set to enable v2 ECIES decryption (typically same value as privateKey)

	logger *logrus.Logger
}

// NewHotDownloader creates a new HotDownloader.
//
// When decryption keys are set on the returned HotDownloader, it owns decryption for
// every path it serves - hot cache hit, fallback, and fragments alike - so fallback
// must NOT itself be configured with decryption keys, or its output would be
// decrypted twice.
func NewHotDownloader(routerClient *node.HotRouterClient, privateKey *ecdsa.PrivateKey, fallback IDownloader, opts ...zg_common.LogOption) *HotDownloader {
	return &HotDownloader{
		routerClient: routerClient,
		privateKey:   privateKey,
		fallback:     fallback,
		logger:       zg_common.NewLogger(opts...),
	}
}

// WithEncryptionKey sets the v1 symmetric encryption key for post-download decryption.
func (d *HotDownloader) WithEncryptionKey(key []byte) *HotDownloader {
	d.encryptionKey = key
	return d
}

// WithWalletPrivateKey enables v2 (ECIES) decryption using the given private key.
// Typically this is the same value passed to NewHotDownloader for router signing.
func (d *HotDownloader) WithWalletPrivateKey(priv *ecdsa.PrivateKey) *HotDownloader {
	d.walletPrivateKey = priv
	return d
}

func (d *HotDownloader) hasDecryptionKey() bool {
	return len(d.encryptionKey) > 0 || d.walletPrivateKey != nil
}

// Download downloads a single file, trying hot storage first and falling back to regular download.
func (d *HotDownloader) Download(ctx context.Context, root, filename string, withProof bool) error {
	// Apply the destination contract before touching anything, exactly as the regular
	// path does: an existing file is never overwritten, whether it already matches
	// (ErrFileAlreadyExists, which download_dir treats as success) or holds something
	// else (a hard error). Creating the destination up front meant the hot path
	// overwrote a matching file and destroyed a differing one.
	if err := checkFileExistence(filename, common.HexToHash(root)); err != nil {
		return errors.WithMessage(err, "failed to check file existence")
	}

	outFile, err := createOutputFile(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}

	ok, hotErr := d.tryHotDownload(ctx, root, outFile)
	closeErr := outFile.Close()

	if !ok {
		// The partial file is discarded either way here, so a close failure only needs
		// recording: the fallback writes the destination itself.
		if closeErr != nil {
			d.logger.WithError(closeErr).Debug("Failed to close partial hot storage output file")
		}
		os.Remove(filename)
		if hotErr != nil {
			d.logger.WithError(hotErr).Warn("Hot storage download failed, falling back to regular download")
		} else {
			d.logger.Info("File not in hot storage, falling back to regular download")
		}
		// The partial file has been removed, so the fallback sees no destination and applies
		// its own existence check from a clean slate. A failure here costs the caller
		// nothing, because checkFileExistence above established there was no file to lose.
		if err := d.fallback.Download(ctx, root, filename, withProof); err != nil {
			return err
		}

		// This layer owns decryption on both paths - the fallback is deliberately
		// constructed without keys (see NewHotDownloader). Returning straight from the
		// fallback would leave ciphertext in the caller's output file and report success,
		// while a cache hit for the same file decrypted correctly.
		if d.hasDecryptionKey() {
			if err := d.decryptFile(filename); err != nil {
				return errors.WithMessage(err, "failed to decrypt fallback data")
			}
		}

		d.logger.Info("Completed download via fallback")
		return nil
	}

	// See util.CloseOutputFile: the download is not complete until it closes cleanly.
	// This has to be settled before the file is read back for decryption below, so a
	// truncated download is not reported as a decryption failure.
	if closeErr != nil {
		os.Remove(filename)
		return errors.WithMessage(closeErr, "failed to close output file")
	}

	if d.hasDecryptionKey() {
		if err := d.decryptFile(filename); err != nil {
			// Remove the file rather than leaving ciphertext behind. Uploads compute the
			// root over the encrypted stream, so undecrypted bytes still match the
			// requested root - checkFileExistence would report ErrFileAlreadyExists on the
			// next run and the caller would be told they already had the file.
			os.Remove(filename)
			return errors.WithMessage(err, "failed to decrypt hot storage data")
		}
	}

	d.logger.Info("Completed download from hot storage")
	return nil
}

// DownloadFragments downloads multiple fragments, trying hot storage first per fragment.
func (d *HotDownloader) DownloadFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	if d.hasDecryptionKey() {
		return d.downloadEncryptedFragments(ctx, roots, filename, withProof)
	}
	return d.downloadPlainFragments(ctx, roots, filename, withProof)
}

func (d *HotDownloader) downloadPlainFragments(ctx context.Context, roots []string, filename string, withProof bool) (err error) {
	outFile, err := createOutputFile(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}
	defer func() { err = util.CloseOutputFile(outFile, filename, err) }()

	tempDir, err := util.TempDirBeside(filename, ".zgs-fragments-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	for i, root := range roots {
		tempFile := filepath.Join(tempDir, root+".temp")

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

func (d *HotDownloader) downloadEncryptedFragments(ctx context.Context, roots []string, filename string, withProof bool) (err error) {
	outFile, err := createOutputFile(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}
	defer func() { err = util.CloseOutputFile(outFile, filename, err) }()

	tempDir, err := util.TempDirBeside(filename, ".zgs-fragments-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	var header *core.EncryptionHeader
	var key [32]byte
	var cumulativeDataOffset uint64

	for i, root := range roots {
		fragmentData, err := d.downloadFragmentData(ctx, root, i, withProof, tempDir)
		if err != nil {
			return err
		}

		if i == 0 {
			header, err = core.ParseEncryptionHeader(fragmentData)
			if err != nil {
				return errors.WithMessage(err, "failed to parse encryption header from fragment 0")
			}
			key, err = ResolveDecryptionKey(d.encryptionKey, d.walletPrivateKey, header)
			if err != nil {
				return err
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
func (d *HotDownloader) downloadFragmentData(ctx context.Context, root string, index int, withProof bool, tempDir string) ([]byte, error) {
	var buf bytes.Buffer
	ok, err := d.tryHotDownload(ctx, root, &buf)
	if !ok {
		if err != nil {
			d.logger.WithError(err).WithField("fragment", index).Warn("Hot storage failed for fragment, falling back")
		} else {
			d.logger.WithField("fragment", index).Info("Fragment not in hot storage, falling back")
		}
		tempFile := filepath.Join(tempDir, root+".temp")
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
	f, err := createOutputFile(path)
	if err != nil {
		return false, fmt.Errorf("failed to create temp file: %w", err)
	}

	ok, err := d.tryHotDownload(ctx, root, f)
	if closeErr := f.Close(); ok && closeErr != nil {
		// This temp file is read straight back into the concatenated output, so a close
		// failure - which can mean a short file - must not pass as a hot storage hit.
		ok, err = false, fmt.Errorf("failed to close temp file: %w", closeErr)
	}
	if !ok {
		os.Remove(path)
	}
	return ok, err
}

// decryptFile decrypts the file at filename in-place, auto-detecting v1 vs v2 from its header.
func (d *HotDownloader) decryptFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to read file for decryption")
	}
	header, err := core.ParseEncryptionHeader(data)
	if err != nil {
		return errors.WithMessage(err, "failed to parse encryption header")
	}
	key, err := ResolveDecryptionKey(d.encryptionKey, d.walletPrivateKey, header)
	if err != nil {
		return err
	}
	decrypted, err := core.DecryptFile(&key, data)
	if err != nil {
		return errors.WithMessage(err, "failed to decrypt file")
	}
	return errors.WithMessage(os.WriteFile(filename, decrypted, 0644), "failed to write decrypted file")
}
