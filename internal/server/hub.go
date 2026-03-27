package server

import (
	"sync"

	"github.com/haolipeng/LLM-Scope/internal/core"
)

// EventHub fans out events to SSE subscribers.
type EventHub struct {
	mu      sync.Mutex
	subs    map[chan *core.Event]struct{}
	logFile string
}

func NewEventHub(logFile string) *EventHub {
	return &EventHub{
		subs:    make(map[chan *core.Event]struct{}),
		logFile: logFile,
	}
}

func (h *EventHub) LogFile() string {
	return h.logFile
}

func (h *EventHub) Publish(event *core.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- event:
		default:
		}
	}
}

func (h *EventHub) Subscribe() chan *core.Event {
	ch := make(chan *core.Event, 100)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *EventHub) Unsubscribe(ch chan *core.Event) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}
