package cmd

import (
	"github.com/0gfoundation/0g-storage-client/gateway"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/spf13/cobra"
)

var (
	gatewayArgs struct {
		nodes []string
	}

	gatewayCmd = &cobra.Command{
		Use:   "gateway",
		Short: "Start gateway service",
		Run:   startGateway,
	}
)

func init() {
	gatewayCmd.Flags().StringSliceVar(&gatewayArgs.nodes, "nodes", []string{
		"http://127.0.0.1:5678",
		"http://127.0.0.1:5679",
		"http://127.0.0.1:5680",
	}, "Storage node list separated by comma")
	gatewayCmd.Flags().StringVar(&gateway.LocalFileRepo, "repo", "", "Local file repository")

	rootCmd.AddCommand(gatewayCmd)
}

func startGateway(*cobra.Command, []string) {
	nodes := node.MustNewZgsClients(gatewayArgs.nodes, nil)
	gateway.MustServeLocal(nodes)
}
