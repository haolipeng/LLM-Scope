package transforms_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/pipeline/transforms"
	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	"github.com/haolipeng/LLM-Scope/internal/event"
)

func loadEvent(t *testing.T, name string) *event.Event {
	t.Helper()

	path := filepath.Join("testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	var event event.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}

	return &event
}

func runAnalyzer(ctx context.Context, a pipelinetypes.Analyzer, input []*event.Event) []*event.Event {
	in := make(chan *event.Event, len(input))
	for _, event := range input {
		in <- event
	}
	close(in)

	out := a.Process(ctx, in)
	var result []*event.Event
	for event := range out {
		result = append(result, event)
	}
	return result
}

func TestHTTPParser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	a := transforms.NewHTTPParser(false)
	input := []*event.Event{
		loadEvent(t, "ssl_http_request.json"),
	}

	out := runAnalyzer(ctx, a, input)
	if !containsSource(out, "http_parser") {
		t.Fatalf("expected http_parser event")
	}
}

func TestSSEMerger(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	a := transforms.NewSSEMerger()
	input := []*event.Event{
		loadEvent(t, "ssl_sse_chunk_1.json"),
		loadEvent(t, "ssl_sse_chunk_2.json"),
	}

	out := runAnalyzer(ctx, a, input)
	if !containsSource(out, "sse_processor") {
		t.Fatalf("expected sse_processor event")
	}
}

func TestToolCallAggregator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	a := transforms.NewToolCallAggregator()
	input := []*event.Event{
		loadEvent(t, "process_exec.json"),
		loadEvent(t, "process_file_open.json"),
	}

	out := runAnalyzer(ctx, a, input)
	if !containsSource(out, "tool_call") {
		t.Fatalf("expected tool_call event")
	}
}

func containsSource(events []*event.Event, source string) bool {
	for _, event := range events {
		if event.Source == source {
			return true
		}
	}
	return false
}
