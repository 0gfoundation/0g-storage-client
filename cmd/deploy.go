package cmd

import (
	"context"
	"time"

	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	deployArgs struct {
		url            string
		key            string
		bytecodeOrFile string
		timeout        time.Duration
	}

	deployCmd = &cobra.Command{
		Use:   "deploy",
		Short: "Deploy ZeroGStorage contract to specified blockchain",
		Run:   deploy,
	}
)

func init() {
	deployCmd.Flags().StringVar(&deployArgs.url, "url", "", "Fullnode URL to interact with blockchain")
	deployCmd.MarkFlagRequired("url")
	deployCmd.Flags().StringVar(&deployArgs.key, "key", "", "Private key to create smart contract")
	deployCmd.MarkFlagRequired("key")
	deployCmd.Flags().StringVar(&deployArgs.bytecodeOrFile, "bytecode", "", "ZeroGStorage smart contract bytecode")
	deployCmd.MarkFlagRequired("bytecode")

	deployCmd.Flags().DurationVar(&deployArgs.timeout, "timeout", 0, "cli task timeout, 0 for no timeout")

	rootCmd.AddCommand(deployCmd)
}

func deploy(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if deployArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, deployArgs.timeout)
		defer cancel()
	}

	client := blockchain.MustNewWeb3(deployArgs.url, deployArgs.key)

	contract, err := blockchain.Deploy(ctx, client, deployArgs.bytecodeOrFile)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to deploy smart contract")
	}

	logrus.WithField("contract", contract).Info("Smart contract deployed")
}
