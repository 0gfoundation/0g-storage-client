package transfer

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/openweb3/web3go"
	"github.com/pkg/errors"

	"github.com/0gfoundation/0g-storage-client/contract"
)

func ResolveContractConfig(ctx context.Context, w3Client *web3go.Client, clients *SelectedNodes, contractConfig *ContractAddress) (*contract.Market, *contract.FlowContract, error) {
	flowAddress, err := resolveFlowAddress(ctx, w3Client, clients, contractConfig)
	if err != nil {
		return nil, nil, err
	}

	flow, err := contract.NewFlowContract(flowAddress, w3Client)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to create flow contract")
	}

	var market *contract.Market
	if contractConfig != nil && contractConfig.MarketAddress != "" {
		backend, _ := w3Client.ToClientForContract()
		market, err = contract.NewMarket(common.HexToAddress(contractConfig.MarketAddress), backend)
		if err != nil {
			return nil, nil, errors.WithMessage(err, "Failed to create market contract")
		}
	} else {
		market, err = flow.GetMarketContract(ctx)
		if err != nil {
			return nil, nil, errors.WithMessagef(err, "Failed to get market contract from flow contract %v", flowAddress)
		}
	}

	return market, flow, nil
}

func resolveFlowAddress(ctx context.Context, w3Client *web3go.Client, clients *SelectedNodes, contractConfig *ContractAddress) (common.Address, error) {
	if contractConfig != nil && contractConfig.FlowAddress != "" {
		return common.HexToAddress(contractConfig.FlowAddress), nil
	}

	statusNode, err := statusClient(clients)
	if err != nil {
		return common.Address{}, err
	}
	status, err := statusNode.GetStatus(ctx)
	if err != nil {
		return common.Address{}, errors.WithMessagef(err, "Failed to get status from storage node %v", statusNode.URL())
	}

	chainId, err := w3Client.Eth.ChainId()
	if err != nil {
		return common.Address{}, errors.WithMessage(err, "Failed to get chain ID from blockchain node")
	}

	if chainId != nil && *chainId != status.NetworkIdentity.ChainId {
		return common.Address{}, errors.Errorf("Chain ID mismatch, blockchain = %v, storage node = %v", *chainId, status.NetworkIdentity.ChainId)
	}

	return status.NetworkIdentity.FlowContractAddress, nil
}
