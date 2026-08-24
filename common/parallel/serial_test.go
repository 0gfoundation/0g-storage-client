package parallel

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type foo struct {
	t      *testing.T
	result []int
}

func (f *foo) ParallelDo(ctx context.Context, routine, task int) (interface{}, error) {
	return task * task, nil
}

func (f *foo) ParallelCollect(result *Result) error {
	assert.Nil(f.t, result.err)
	assert.Equal(f.t, len(f.result), result.Task)
	assert.Equal(f.t, result.Task*result.Task, result.Value.(int))

	f.result = append(f.result, result.Value.(int))

	return nil
}

func TestSerial(t *testing.T) {
	f := foo{t, nil}

	tasks := 100

	err := Serial(context.Background(), &f, tasks, SerialOption{4, 16})
	assert.Nil(t, err)
	assert.Equal(t, tasks, len(f.result))

	for i := 0; i < tasks; i++ {
		assert.Equal(t, i*i, f.result[i])
	}
}

// Routines < 0 used to survive Normalize, which substituted a default only for exactly
// 0, and then no workers were started at all - so collect waited forever. With Window
// negative as well the channel length went negative and make(chan) panicked. Either way
// the caller's mistake has to surface instead.
func TestSerial_RejectsNegativeOptions(t *testing.T) {
	for _, opt := range []SerialOption{
		{Routines: -1},
		{Routines: -1, Window: 16},
		{Routines: 4, Window: -1},
		{Routines: -1, Window: -1}, // this pair used to panic in make(chan)
	} {
		opt := opt
		t.Run(fmt.Sprintf("routines=%d,window=%d", opt.Routines, opt.Window), func(t *testing.T) {
			f := foo{t: t}

			// A guard: the bug was a hang, so a plain call would never return.
			done := make(chan error, 1)
			go func() { done <- Serial(context.Background(), &f, 100, opt) }()

			select {
			case err := <-done:
				require.Error(t, err, "a negative option must be reported")
				assert.Contains(t, err.Error(), "negative parallel option")
			case <-time.After(10 * time.Second):
				t.Fatal("Serial did not return: negative options still hang")
			}
		})
	}
}

// Normalize is exported, so a caller using it directly must not be left with no
// workers either.
func TestSerialOption_NormalizeSubstitutesDefaultForNonPositiveRoutines(t *testing.T) {
	for _, routines := range []int{0, -1, -100} {
		opt := SerialOption{Routines: routines}
		opt.Normalize(1000)
		assert.Positive(t, opt.Routines, "routines=%d must be replaced by a usable default", routines)
	}
}

// The valid path is unchanged.
func TestSerialOption_NormalizeClampsToTasks(t *testing.T) {
	opt := SerialOption{Routines: 64, Window: 128}
	opt.Normalize(10)

	assert.Equal(t, 10, opt.Routines)
	assert.Equal(t, 10, opt.Window)
}
