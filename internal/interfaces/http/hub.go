package httpserver

import (
	"log"
	"sync"
	"sync/atomic"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// EventHub fans out events to SSE subscribers.
type EventHub struct {
	mu      sync.Mutex
	subs    map[chan *runtimeevent.Event]struct{}
	logFile string
	dropped atomic.Int64
}

func NewEventHub(logFile string) *EventHub {
	return &EventHub{
		subs:    make(map[chan *runtimeevent.Event]struct{}),
		logFile: logFile,
	}
}

func (h *EventHub) LogFile() string {
	return h.logFile
}

func (h *EventHub) Publish(event *runtimeevent.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- event:
		default:
			n := h.dropped.Add(1)
			if n == 1 || n%100 == 0 {
				log.Printf("警告: 订阅者队列已满，已累计丢弃 %d 个事件", n)
			}
		}
	}
}

func (h *EventHub) Subscribe() chan *runtimeevent.Event {
	ch := make(chan *runtimeevent.Event, 100)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *EventHub) Unsubscribe(ch chan *runtimeevent.Event) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}
