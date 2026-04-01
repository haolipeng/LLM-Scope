package core

import (
	"context"
	"sync"

	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

type sinkTap struct {
	sinks []pipelinetypes.Sink
}

// AttachSinks 以旁路监听的方式把多个 Sink 挂到事件流上。
//
// 返回的 Analyzer 会原样透传事件，同时把事件分发给所有 Sink。
func AttachSinks(sinks ...pipelinetypes.Sink) pipelinetypes.Analyzer {
	return sinkTap{sinks: sinks}
}

func (s sinkTap) Name() string { return "sink_tap" }

func (s sinkTap) Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event {
	if len(s.sinks) == 0 {
		return in
	}

	sinkChans := make([]chan *runtimeevent.Event, 0, len(s.sinks))
	for range s.sinks {
		sinkChans = append(sinkChans, make(chan *runtimeevent.Event, 100))
	}

	var wg sync.WaitGroup
	for i, sink := range s.sinks {
		ch := sinkChans[i]
		wg.Add(1)
		go func(sk pipelinetypes.Sink, c <-chan *runtimeevent.Event) {
			defer wg.Done()
			sk.Consume(ctx, c)
		}(sink, ch)
	}

	out := make(chan *runtimeevent.Event)
	go func() {
		defer close(out)
		defer func() {
			for _, ch := range sinkChans {
				close(ch)
			}
			wg.Wait() // 等待所有 Sink 完成清理（含 DuckDB flush）
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-in:
				if !ok {
					return
				}
				for _, ch := range sinkChans {
					select {
					case ch <- event:
					case <-ctx.Done():
						return
					}
				}
				out <- event
			}
		}
	}()

	return out
}
