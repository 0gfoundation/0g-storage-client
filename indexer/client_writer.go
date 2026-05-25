package indexer

import (
	"context"
	"io"

	"github.com/pkg/errors"
)

// DownloadToWriter streams a full file to w by discovering storage nodes via
// the indexer and delegating to (*transfer.Downloader).DownloadToWriter.
//
// Encryption is not supported — see (*transfer.Downloader).DownloadToWriter
// for why. Use Download(filename) for encrypted files since header parsing
// requires buffering before any plaintext can be emitted.
func (c *Client) DownloadToWriter(ctx context.Context, root string, w io.Writer, withProof bool) error {
	if c.hasDecryptionKey() {
		return errors.New("DownloadToWriter does not support encrypted files — use Download(filename) instead")
	}
	downloader, err := c.NewDownloaderFromIndexerNodes(ctx, root)
	if err != nil {
		return err
	}
	// Propagate encryption keys defensively even though we already
	// rejected encrypted files above — keeps the downloader in a
	// consistent state if the contract changes later.
	if len(c.encryptionKey) > 0 {
		downloader.WithEncryptionKey(c.encryptionKey)
	}
	if c.walletPrivateKey != nil {
		downloader.WithWalletPrivateKey(c.walletPrivateKey)
	}
	return downloader.DownloadToWriter(ctx, root, w, withProof)
}

// DownloadRangeToWriter streams bytes [offset, offset+length) of `root` to w.
// Internally discovers nodes via the indexer just like Download.
func (c *Client) DownloadRangeToWriter(ctx context.Context, root string, offset, length int64, w io.Writer) error {
	if c.hasDecryptionKey() {
		return errors.New("DownloadRangeToWriter does not support encrypted files")
	}
	downloader, err := c.NewDownloaderFromIndexerNodes(ctx, root)
	if err != nil {
		return err
	}
	return downloader.DownloadRangeToWriter(ctx, root, offset, length, w)
}
