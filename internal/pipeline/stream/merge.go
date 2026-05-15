package stream

import (
	"context"
	"sync"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

// forwardStream 将单个输入流中的事件转发到输出流，直到输入关闭或 ctx 取消。
func forwardStream(ctx context.Context, in <-chan *event.Event, out chan<- *event.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-in:
			if !ok {
				return
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

// MergeStreams 将多个事件流扇入合并为一个输出流。
//
// 当 ctx 被取消时会停止转发；当所有输入流都结束后，会关闭输出流。
func MergeStreams(ctx context.Context, streams ...<-chan *event.Event) <-chan *event.Event {
	out := make(chan *event.Event, 100)

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
		go func(ch <-chan *event.Event) {
			defer wg.Done()
			forwardStream(ctx, ch, out)
		}(stream)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
