package cmd

import (
	"math/rand"
	"os"
	"time"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	genFileArgs struct {
		size      uint64
		file      string
		overwrite bool
	}

	genFileCmd = &cobra.Command{
		Use:   "gen",
		Short: "Generate a temp file for test purpose",
		Run:   generateTempFile,
	}
)

func init() {
	genFileCmd.Flags().Uint64Var(&genFileArgs.size, "size", 0, "File size in bytes (default \"[1M, 10M)\")")
	genFileCmd.Flags().StringVar(&genFileArgs.file, "file", "tmp123456", "File name to generate")
	genFileCmd.Flags().BoolVar(&genFileArgs.overwrite, "overwrite", false, "Whether to overwrite existing file")

	rootCmd.AddCommand(genFileCmd)
}

func generateTempFile(*cobra.Command, []string) {
	exists, err := core.Exists(genFileArgs.file)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to check file existence")
	}

	if exists {
		if !genFileArgs.overwrite {
			logrus.WithField("file", genFileArgs.file).Warn("File already exists")
			return
		}

		logrus.WithField("file", genFileArgs.file).Info("Overwrite file")
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	if genFileArgs.size == 0 {
		// [1M, 10M)
		genFileArgs.size = 1024*1024 + uint64(9.0*1024*1024*r.Float64())
	}

	data := make([]byte, genFileArgs.size)
	if n, err := r.Read(data); err != nil {
		logrus.WithError(err).Fatal("Failed to generate random data")
	} else if n != len(data) {
		logrus.WithField("n", n).Fatal("Invalid data len")
	}

	if err := os.WriteFile(genFileArgs.file, data, os.ModePerm); err != nil {
		logrus.WithError(err).Fatal("Failed to write file")
	}

	file, err := core.Open(genFileArgs.file)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to open file")
	}

	tree, err := core.MerkleTree(file)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate merkle tree")
	}

	logrus.WithField("root", tree.Root()).WithField("file", genFileArgs.file).Info("Succeeded to write file")
}
