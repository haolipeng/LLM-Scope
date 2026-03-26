package analyzer_test

import (
  "context"
  "encoding/json"
  "os"
  "path/filepath"
  "testing"
  "time"

  "github.com/eunomia-bpf/agentsight/internal/analyzer"
  "github.com/eunomia-bpf/agentsight/internal/core"
)

func loadEvent(t *testing.T, name string) *core.Event {
  t.Helper()

  path := filepath.Join("testdata", name)
  raw, err := os.ReadFile(path)
  if err != nil {
    t.Fatalf("read %s: %v", name, err)
  }

  var event core.Event
  if err := json.Unmarshal(raw, &event); err != nil {
    t.Fatalf("unmarshal %s: %v", name, err)
  }

  return &event
}

func runAnalyzer(ctx context.Context, a analyzer.Analyzer, input []*core.Event) []*core.Event {
  in := make(chan *core.Event, len(input))
  for _, event := range input {
    in <- event
  }
  close(in)

  out := a.Process(ctx, in)
  var result []*core.Event
  for event := range out {
    result = append(result, event)
  }
  return result
}

func TestHTTPParser(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
  defer cancel()

  a := analyzer.NewHTTPParser(false)
  input := []*core.Event{
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

  a := analyzer.NewSSEMerger()
  input := []*core.Event{
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

  a := analyzer.NewToolCallAggregator()
  input := []*core.Event{
    loadEvent(t, "process_exec.json"),
    loadEvent(t, "process_file_open.json"),
  }

  out := runAnalyzer(ctx, a, input)
  if !containsSource(out, "tool_call") {
    t.Fatalf("expected tool_call event")
  }
}

func containsSource(events []*core.Event, source string) bool {
  for _, event := range events {
    if event.Source == source {
      return true
    }
  }
  return false
}
