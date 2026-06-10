package indexer

import (
	"testing"

	eth_common "github.com/ethereum/go-ethereum/common"
)

func nz(b byte) eth_common.Hash { // non-zero hash with a distinguishing byte
	var x eth_common.Hash
	x[31] = b
	return x
}

var zeroHash = eth_common.Hash{}

func eqHashes(a, b []eth_common.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAnyNonZero(t *testing.T) {
	cases := []struct {
		name string
		in   []eth_common.Hash
		want bool
	}{
		{"nil", nil, false},
		{"empty", []eth_common.Hash{}, false},
		{"one-zero", []eth_common.Hash{zeroHash}, false},
		{"two-zero", []eth_common.Hash{zeroHash, zeroHash}, false},
		{"one-nonzero", []eth_common.Hash{nz(1)}, true},
		{"mixed", []eth_common.Hash{zeroHash, nz(2)}, true},
	}
	for _, c := range cases {
		if got := anyNonZero(c.in); got != c.want {
			t.Errorf("%s: anyNonZero(%v) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestPreferLanded(t *testing.T) {
	landedTx := []eth_common.Hash{nz(1)}
	landedRoots := []eth_common.Hash{nz(10)}

	t.Run("recovery skip returns landed tx", func(t *testing.T) {
		// Submit landed on an earlier iteration; the recovering iteration
		// skipped (all-zero tx). Must surface the landed tx, not the zero.
		gotTx, gotRoots := preferLanded([]eth_common.Hash{zeroHash}, []eth_common.Hash{nz(10)}, landedTx, landedRoots)
		if !eqHashes(gotTx, landedTx) {
			t.Errorf("tx = %v, want landed %v", gotTx, landedTx)
		}
		if !eqHashes(gotRoots, landedRoots) {
			t.Errorf("roots = %v, want landed %v", gotRoots, landedRoots)
		}
	})

	t.Run("current iteration landed returns current", func(t *testing.T) {
		curTx := []eth_common.Hash{nz(2)}
		curRoots := []eth_common.Hash{nz(20)}
		gotTx, gotRoots := preferLanded(curTx, curRoots, landedTx, landedRoots)
		if !eqHashes(gotTx, curTx) {
			t.Errorf("tx = %v, want current %v", gotTx, curTx)
		}
		if !eqHashes(gotRoots, curRoots) {
			t.Errorf("roots = %v, want current %v", gotRoots, curRoots)
		}
	})

	t.Run("no landed ever returns current (pre-existing dedup stays zero)", func(t *testing.T) {
		// True dedup: skipped from the first attempt, no submit ever.
		// Must keep returning the zero so the caller refunds, not bills.
		gotTx, _ := preferLanded([]eth_common.Hash{zeroHash}, []eth_common.Hash{nz(10)}, nil, nil)
		if anyNonZero(gotTx) {
			t.Errorf("tx = %v, want all-zero (no landed submit)", gotTx)
		}
	})
}
