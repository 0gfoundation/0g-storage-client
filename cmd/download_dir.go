package cmd

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	downloadDirArgs downloadArgument

	downloadDirCmd = &cobra.Command{
		Use:   "download-dir",
		Short: "Download directory from ZeroGStorage network",
		Run:   downloadDir,
	}
)

func init() {
	bindDownloadFlags(downloadDirCmd, &downloadDirArgs)

	rootCmd.AddCommand(downloadDirCmd)
}

func downloadDir(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if downloadDirArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, downloadDirArgs.timeout)
		defer cancel()
	}

	downloader, closer, err := newDownloader(downloadDirArgs)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize downloader")
	}
	defer closer()

	// Download the entire directory structure.
	err = transfer.DownloadDir(ctx, downloader, downloadDirArgs.root, downloadDirArgs.file, downloadDirArgs.proof)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to download folder")
	}
}
