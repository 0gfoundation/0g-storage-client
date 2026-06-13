package main

// E2E for issue #159: the OnSubmitted broadcast callback + caller-context
// awareness in the upload submit path.
//
// Three cases, all against a real local chain + storage node:
//
//  1. wait_receipt   — a >2MiB upload takes the receipt-wait path
//                      (uploadSlow → submitLogEntryAndWait →
//                      TransactWithGasAdjustment). OnSubmitted must fire
//                      once, at broadcast, with the SAME hash the upload
//                      ultimately returns.
//  2. no_receipt     — a small upload takes the no-receipt path
//                      (uploadSlowParallel → TransactWithGasAdjustmentNoReceipt).
//                      Same contract: OnSubmitted fires once with the
//                      returned hash.
//  3. cancel_preserves_hash — the caller cancels the instant the tx
//                      broadcasts (cancel() invoked from inside
//                      OnSubmitted). This models a drain firing mid-upload.
//                      Asserts the corrected design:
//                        * the upload returns an error (the long-pole
//                          segment upload honors the cancel and aborts), AND
//                        * the broadcast callback captured the on-chain
//                          hash, AND
//                        * the receipt wait was NOT terminated by the
//                          cancel — proven by the return STILL carrying the
//                          same tx hash (the wait ran on its own context to
//                          completion). That last assertion is the
//                          regression guard for "don't terminate the wait;
//                          we just want the hash" (issue #159).

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"

	zgcommon "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/transfer"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/openweb3/web3go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func newUploader(ctx context.Context, w3 *web3go.Client, nodeUrls []string) (*transfer.Uploader, func(), error) {
	return transfer.NewUploaderFromConfig(ctx, w3, transfer.UploaderConfig{
		Nodes:     nodeUrls,
		LogOption: zgcommon.LogOption{Logger: logrus.StandardLogger()},
	})
}

// caseCallbackFires uploads `size` bytes and asserts OnSubmitted fired
// exactly once, at broadcast, with the same non-zero hash the upload
// returns. Covers both submit paths via the size (small → no-receipt,
// large → receipt-wait).
func caseCallbackFires(ctx context.Context, w3 *web3go.Client, nodeUrls []string, name string, size int) error {
	logrus.Infof("=== %s (size=%d) ===", name, size)

	data, err := randomBytes(size)
	if err != nil {
		return errors.WithMessagef(err, "%s: random bytes", name)
	}
	iter, err := core.NewDataInMemory(data)
	if err != nil {
		return errors.WithMessagef(err, "%s: NewDataInMemory", name)
	}

	uploader, closer, err := newUploader(ctx, w3, nodeUrls)
	if err != nil {
		return errors.WithMessagef(err, "%s: NewUploaderFromConfig", name)
	}
	defer closer()

	var broadcast []ethcommon.Hash
	opt := transfer.UploadOption{
		FinalityRequired: transfer.FileFinalized,
		TransactionOption: transfer.TransactionOption{
			OnSubmitted: func(h ethcommon.Hash) { broadcast = append(broadcast, h) },
		},
	}

	txHashes, _, err := uploader.SplitableUpload(ctx, iter, opt)
	if err != nil {
		return errors.WithMessagef(err, "%s: SplitableUpload", name)
	}

	if len(broadcast) != 1 {
		return fmt.Errorf("%s: OnSubmitted fired %d times, want exactly 1 (single fragment, single tx)", name, len(broadcast))
	}
	if (broadcast[0] == ethcommon.Hash{}) {
		return fmt.Errorf("%s: OnSubmitted got the zero hash", name)
	}
	if len(txHashes) != 1 || txHashes[0] != broadcast[0] {
		return fmt.Errorf("%s: broadcast hash %s != returned hash %v", name, broadcast[0].Hex(), txHashes)
	}
	logrus.Infof("%s: PASSED — OnSubmitted fired once at broadcast with %s (== returned hash)", name, broadcast[0].Hex())
	return nil
}

// caseCancelPreservesHash cancels from inside OnSubmitted (the instant the
// tx broadcasts) and proves the broadcast hash is preserved via the
// callback even though the cancelled upload returns no hash, and that the
// tx really landed on chain.
func caseCancelPreservesHash(parent context.Context, w3 *web3go.Client, nodeUrls []string) error {
	const name = "cancel_preserves_hash"
	logrus.Infof("=== %s ===", name)

	data, err := randomBytes(3 * 1024 * 1024) // >2MiB → receipt-wait path
	if err != nil {
		return errors.WithMessagef(err, "%s: random bytes", name)
	}
	iter, err := core.NewDataInMemory(data)
	if err != nil {
		return errors.WithMessagef(err, "%s: NewDataInMemory", name)
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	uploader, closer, err := newUploader(ctx, w3, nodeUrls)
	if err != nil {
		return errors.WithMessagef(err, "%s: NewUploaderFromConfig", name)
	}
	defer closer()

	var captured ethcommon.Hash
	opt := transfer.UploadOption{
		FinalityRequired: transfer.FileFinalized,
		TransactionOption: transfer.TransactionOption{
			OnSubmitted: func(h ethcommon.Hash) {
				captured = h
				cancel() // drain fired the instant the tx broadcast
			},
		},
	}

	start := time.Now()
	txHashes, _, err := uploader.SplitableUpload(ctx, iter, opt)
	elapsed := time.Since(start)

	// The upload must NOT succeed — the long-pole segment upload honors
	// the cancel and aborts.
	if err == nil {
		return fmt.Errorf("%s: SplitableUpload returned nil error despite cancel-at-broadcast", name)
	}
	logrus.Infof("%s: upload aborted after %s with: %v", name, elapsed, err)

	// The callback must have captured the real broadcast hash.
	if (captured == ethcommon.Hash{}) {
		return fmt.Errorf("%s: OnSubmitted never captured a hash — record-at-broadcast failed", name)
	}

	// Regression guard for "don't terminate the receipt wait" (#159): the
	// receipt wait ran on its own context to completion despite the cancel,
	// so the upload's RETURN must STILL carry the same broadcast hash. If a
	// future change made the wait honor the caller's context, the wait
	// would abort with a nil receipt and the return would drop the hash —
	// this assertion would then fail.
	if len(txHashes) != 1 || txHashes[0] != captured {
		return fmt.Errorf("%s: receipt wait was terminated by cancel — return hash %v != broadcast hash %s (the wait must complete; see #159)",
			name, txHashes, captured.Hex())
	}

	// And that tx must actually be on chain: the operator paid for it, so
	// the caller can resolve + bill it on resume.
	verifyCtx := context.Background()
	found := false
	for i := 0; i < 30; i++ {
		tx, terr := w3.Eth.TransactionByHash(captured)
		if terr == nil && tx != nil {
			found = true
			break
		}
		select {
		case <-verifyCtx.Done():
			return verifyCtx.Err()
		case <-time.After(time.Second):
		}
	}
	if !found {
		return fmt.Errorf("%s: captured broadcast hash %s not found on chain", name, captured.Hex())
	}

	logrus.Infof("%s: PASSED — cancel-at-broadcast preserved %s via callback; tx is on chain", name, captured.Hex())
	return nil
}

func runTest() error {
	ctx := context.Background()
	args := os.Args[1:]
	key := args[0]
	chainURL := args[1]
	nodeUrls := strings.Split(args[2], ",")

	w3 := blockchain.MustNewWeb3(chainURL, key)
	defer w3.Close()

	if err := caseCallbackFires(ctx, w3, nodeUrls, "no_receipt", 100*1024); err != nil {
		return err
	}
	if err := caseCallbackFires(ctx, w3, nodeUrls, "wait_receipt", 3*1024*1024); err != nil {
		return err
	}
	if err := caseCancelPreservesHash(ctx, w3, nodeUrls); err != nil {
		return err
	}
	return nil
}

func main() {
	if err := util.WaitUntil(runTest, time.Minute*5); err != nil {
		logrus.WithError(err).Fatalf("context callback test failed")
	}
}
