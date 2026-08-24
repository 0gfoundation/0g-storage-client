package contract

import (
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/assert"
)

// TestRegisteredABIsCarryTheirErrors pins what init() has to work with. The
// registration itself runs at import time and is not observable from here, but
// an ABI that stopped declaring its errors would silently turn every revert
// back into raw selector bytes, which is the failure this guards.
func TestRegisteredABIsCarryTheirErrors(t *testing.T) {
	for name, expected := range map[string]struct {
		metadata *bind.MetaData
		errors   []string
	}{
		"flow":   {FlowMetaData, []string{"InvalidSubmission", "NotEnoughFee", "EnforcedPause"}},
		"market": {MarketMetaData, nil},
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := expected.metadata.GetAbi()
			assert.NoError(t, err, "init() skips registration when this fails")

			for _, errName := range expected.errors {
				assert.Contains(t, parsed.Errors, errName)
			}
		})
	}
}
