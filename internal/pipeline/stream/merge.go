package stream

import (
	"context"
	"sync"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// MergeStreams 将多个事件流扇入合并为一个输出流。
//
// 当 ctx 被取消时会停止转发；当所有输入流都结束后，会关闭输出流。
func MergeStreams(ctx context.Context, streams ...<-chan *runtimeevent.Event) <-chan *runtimeevent.Event {
	out := make(chan *runtimeevent.Event, 100)

	// 快路径：没有输入流时直接返回已关闭的输出流。
	if len(streams) == 0 {
		close(out)
		return out
	}

	var wg sync.WaitGroup
	for _, stream := range streams {
		if stream == nil {
			continue
		}
		wg.Add(1)
		go func(ch <-chan *runtimeevent.Event) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-ch:
					if !ok {
						return
					}
					select {
					case out <- event:
					case <-ctx.Done():
						return
					}
				}
			}
		}(stream)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
