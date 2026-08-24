package parallel

import (
	"context"
	"runtime"
	"sync"

	"github.com/pkg/errors"
)

func Serial(ctx context.Context, parallelizable Interface, tasks int, option ...SerialOption) error {
	if tasks <= 0 {
		return nil
	}

	var opt SerialOption
	if len(option) > 0 {
		opt = option[0]
	}

	// Reject negative options rather than proceeding with them. Routines < 0 survived
	// Normalize, which only substituted a default for exactly 0, and then started no
	// workers at all - so collect waited forever for results nobody was producing. With
	// Window also negative the channel length went negative too, and make(chan) panics
	// on that. Surfacing the caller's mistake beats hanging or crashing on it.
	if opt.Routines < 0 || opt.Window < 0 {
		return errors.Errorf("negative parallel option: routines = %v, window = %v", opt.Routines, opt.Window)
	}

	opt.Normalize(tasks)

	channelLen := max(opt.Routines, opt.Window)
	taskCh := make(chan int, channelLen)
	defer close(taskCh)
	resultCh := make(chan *Result, channelLen)
	defer close(resultCh)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)

	// start routines to do tasks
	for i := 0; i < opt.Routines; i++ {
		wg.Add(1)
		go work(ctx, i, parallelizable, taskCh, resultCh, &wg)
	}

	err := collect(parallelizable, taskCh, resultCh, tasks, channelLen, opt.Window > 0)

	// notify all routines to terminate
	cancel()

	// wait for termination for all routines
	wg.Wait()

	return err
}

func work(ctx context.Context, routine int, parallelizable Interface, taskCh <-chan int, resultCh chan<- *Result, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case task := <-taskCh:
			val, err := parallelizable.ParallelDo(ctx, routine, task)
			resultCh <- &Result{routine, task, val, err}
			if err != nil {
				return
			}
		}
	}
}

func collect(parallelizable Interface, taskCh chan<- int, resultCh <-chan *Result, tasks, channelLen int, hasWindow bool) error {
	// if hasWindow = true, channelLen == window, fill window first
	// if hasWindow = false, channelLen = routines
	for i := 0; i < channelLen && i < tasks; i++ {
		taskCh <- i
	}

	var next, cnt int
	cache := map[int]*Result{}

	for result := range resultCh {
		if result.err != nil {
			return result.err
		}

		cache[result.Task] = result

		// handle task in sequence
		for cache[next] != nil {
			if err := parallelizable.ParallelCollect(cache[next]); err != nil {
				return err
			}

			// dispatch new task
			if hasWindow {
				if newTask := next + channelLen; newTask < tasks {
					taskCh <- newTask
				}
			}

			// clear cache and move window forward
			delete(cache, next)
			next++
		}
		if !hasWindow {
			if newTask := cnt + channelLen; newTask < tasks {
				taskCh <- newTask
			}
		}
		cnt += 1
		if next >= tasks {
			break
		}
	}

	return nil
}

type SerialOption struct {
	Routines int
	Window   int
}

func (opt *SerialOption) Normalize(tasks int) {
	// 0 < routines <= tasks. Non-positive means "unset", so substitute the default:
	// leaving it at 0 or below would start no workers at all.
	if opt.Routines <= 0 {
		opt.Routines = runtime.GOMAXPROCS(0)
	}

	if opt.Routines > tasks {
		opt.Routines = tasks
	}

	// window disabled
	if opt.Window == 0 {
		return
	}

	// routines <= window <= tasks
	if opt.Window < opt.Routines {
		opt.Window = opt.Routines
	}

	if opt.Window > tasks {
		opt.Window = tasks
	}
}
