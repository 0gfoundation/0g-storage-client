package contract

import (
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/sirupsen/logrus"
)

// Register the custom errors of the contracts this package talks to, so that a
// reverted transaction is reported by name - NotEnoughFee(), InvalidSubmission()
// - rather than as the four selector bytes the chain actually returns.
//
// The blockchain package cannot do this for itself: it is imported here, not
// the reverse.
func init() {
	for name, metadata := range map[string]*bind.MetaData{
		"flow":   FlowMetaData,
		"market": MarketMetaData,
	} {
		parsed, err := metadata.GetAbi()
		if err != nil {
			// A malformed ABI would break every binding in this package long
			// before it mattered here, so this costs only the diagnostic.
			logrus.WithError(err).WithField("contract", name).
				Debug("Cannot register custom errors; reverts will report raw selectors")
			continue
		}

		blockchain.RegisterCustomErrors(parsed)
	}
}
