package analyzer

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/eunomia-bpf/agentsight/internal/core"
)

type AuthRemover struct {
	headers []string
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

func (a *AuthRemover) Name() string {
	return "auth_remover"
}

func (a *AuthRemover) Process(ctx context.Context, in <-chan *core.Event) <-chan *core.Event {
	out := make(chan *core.Event)

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

	for key := range headersRaw {
		if _, exists := toRemove[strings.ToLower(key)]; exists {
			delete(headersRaw, key)
		}
	}

	data["headers"] = headersRaw
	updated, err := json.Marshal(data)
	if err != nil {
		return raw
	}
	return updated
}
