package transforms

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/haolipeng/LLM-Scope/internal/event"
	"github.com/haolipeng/LLM-Scope/internal/logging"
)

// AuthRemover 从 HTTP 事件中移除敏感认证头。
type AuthRemover struct {
	headers []string
	debug   bool
	inner   *mapAnalyzer
}

func NewAuthRemover() *AuthRemover {
	a := &AuthRemover{
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
	a.inner = NewMapAnalyzer("auth_remover", a.processEvent)
	return a
}

func NewAuthRemoverWithDebug(debug bool) *AuthRemover {
	a := NewAuthRemover()
	a.debug = debug
	a.inner = NewMapAnalyzer("auth_remover", a.processEvent)
	return a
}

func (a *AuthRemover) Name() string {
	return "auth_remover"
}

func (a *AuthRemover) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	return a.inner.Process(ctx, in)
}

func (a *AuthRemover) processEvent(ev *event.Event) []*event.Event {
	if ev.Source == "http_parser" {
		ev.Data = a.stripHeaders(ev.Data)
	}
	return []*event.Event{ev}
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
		logging.Named("auth_remover").Infof("removed headers: %s", strings.Join(removed, ", "))
	}

	data["headers"] = headersRaw
	updated, err := json.Marshal(data)
	if err != nil {
		return raw
	}
	return updated
}
