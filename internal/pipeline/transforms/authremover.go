package transforms

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// AuthRemover 从 HTTP 事件中移除敏感认证头。
type AuthRemover struct {
	headers []string
	debug   bool
}

func NewAuthRemover() *AuthRemover {
	return &AuthRemover{
		headers: []string{
			"authorization",
			"x-api-key",
			"x-auth-token",
			"bearer",
			"token",
			"x-access-token",
			"x-session-token",
			"cookie",
			"set-cookie",
		},
	}
}

func NewAuthRemoverWithDebug(debug bool) *AuthRemover {
	a := NewAuthRemover()
	a.debug = debug
	return a
}

func (a *AuthRemover) Name() string {
	return "auth_remover"
}

func (a *AuthRemover) Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event {
	out := make(chan *runtimeevent.Event)

	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-in:
				if !ok {
					return
				}
				if event.Source == "http_parser" {
					event.Data = a.stripHeaders(event.Data)
				}
				out <- event
			}
		}
	}()

	return out
}

func (a *AuthRemover) stripHeaders(raw json.RawMessage) json.RawMessage {
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return raw
	}

	headersRaw, ok := data["headers"].(map[string]interface{})
	if !ok {
		return raw
	}

	toRemove := map[string]struct{}{}
	for _, header := range a.headers {
		toRemove[strings.ToLower(header)] = struct{}{}
	}

	var removed []string
	for key := range headersRaw {
		if _, exists := toRemove[strings.ToLower(key)]; exists {
			if a.debug {
				removed = append(removed, key)
			}
			delete(headersRaw, key)
		}
	}

	if a.debug && len(removed) > 0 {
		log.Printf("[AuthRemover] removed headers: %s", strings.Join(removed, ", "))
	}

	data["headers"] = headersRaw
	updated, err := json.Marshal(data)
	if err != nil {
		return raw
	}
	return updated
}
