package transforms

import (
	"context"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

// MapAnalyzer implements a stateless Analyzer that processes events one at a time.
type MapAnalyzer struct {
	name string
	fn   func(*event.Event) []*event.Event
}

// NewMapAnalyzer creates a stateless Analyzer: per-event processing, no ticker.
// fn returns nil to filter (drop the event), or multiple events to fan out.
func NewMapAnalyzer(name string, fn func(*event.Event) []*event.Event) *MapAnalyzer {
	return &MapAnalyzer{name: name, fn: fn}
}

func (a *MapAnalyzer) Name() string { return a.name }

func (a *MapAnalyzer) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	out := make(chan *event.Event)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-in:
				if !ok {
					return
				}
				results := a.fn(ev)
				for _, r := range results {
					out <- r
				}
			}
		}
	}()
	return out
}

// StatefulOpts configures a stateful Analyzer created by NewStatefulAnalyzer.
type StatefulOpts struct {
	BufSize      int                                     // output channel buffer size (default 0)
	TickInterval time.Duration                           // 0 means no ticker
	OnEvent      func(e *event.Event, emit func(*event.Event))
	OnTick       func(emit func(*event.Event))           // required when TickInterval > 0
	OnClose      func(emit func(*event.Event))           // optional, called on ctx cancel or in closed
}

// StatefulAnalyzer implements an Analyzer with ticker and close support.
type StatefulAnalyzer struct {
	name string
	opts StatefulOpts
}

// NewStatefulAnalyzer creates a stateful Analyzer with ticker and close support.
func NewStatefulAnalyzer(name string, opts StatefulOpts) *StatefulAnalyzer {
	return &StatefulAnalyzer{name: name, opts: opts}
}

func (a *StatefulAnalyzer) Name() string { return a.name }

func (a *StatefulAnalyzer) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	out := make(chan *event.Event, a.opts.BufSize)

	emit := func(ev *event.Event) {
		out <- ev
	}

	go func() {
		defer close(out)
		defer func() {
			if a.opts.OnClose != nil {
				a.opts.OnClose(emit)
			}
		}()

		// nil channel never fires in select, so we can unify both branches.
		var tickCh <-chan time.Time
		if a.opts.TickInterval > 0 && a.opts.OnTick != nil {
			ticker := time.NewTicker(a.opts.TickInterval)
			defer ticker.Stop()
			tickCh = ticker.C
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-tickCh:
				a.opts.OnTick(emit)
			case ev, ok := <-in:
				if !ok {
					return
				}
				a.opts.OnEvent(ev, emit)
			}
		}
	}()

	return out
}
