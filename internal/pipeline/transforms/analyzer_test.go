package transforms_test

import (
	"context"
	"testing"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
	"github.com/haolipeng/LLM-Scope/internal/pipeline/transforms"
)

func TestNewMapAnalyzer_Passthrough(t *testing.T) {
	a := transforms.NewMapAnalyzer("test", func(e *event.Event) []*event.Event {
		return []*event.Event{e}
	})
	if a.Name() != "test" {
		t.Fatalf("expected name 'test', got %q", a.Name())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ev := &event.Event{Source: "x", PID: 1}
	out := runAnalyzer(ctx, a, []*event.Event{ev})
	if len(out) != 1 || out[0] != ev {
		t.Fatalf("expected 1 passthrough event, got %d", len(out))
	}
}

func TestNewMapAnalyzer_Filter(t *testing.T) {
	a := transforms.NewMapAnalyzer("filter", func(e *event.Event) []*event.Event {
		if e.Source == "drop" {
			return nil
		}
		return []*event.Event{e}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	input := []*event.Event{
		{Source: "keep"},
		{Source: "drop"},
		{Source: "keep"},
	}
	out := runAnalyzer(ctx, a, input)
	if len(out) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out))
	}
}

func TestNewMapAnalyzer_FanOut(t *testing.T) {
	a := transforms.NewMapAnalyzer("fanout", func(e *event.Event) []*event.Event {
		return []*event.Event{e, {Source: "extra"}}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	out := runAnalyzer(ctx, a, []*event.Event{{Source: "orig"}})
	if len(out) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out))
	}
	if out[1].Source != "extra" {
		t.Fatalf("expected extra event, got %q", out[1].Source)
	}
}

func TestNewStatefulAnalyzer_OnClose(t *testing.T) {
	closeCalled := false
	a := transforms.NewStatefulAnalyzer("stateful", transforms.StatefulOpts{
		OnEvent: func(e *event.Event, emit func(*event.Event)) {
			emit(e)
		},
		OnClose: func(emit func(*event.Event)) {
			closeCalled = true
			emit(&event.Event{Source: "close_event"})
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	out := runAnalyzer(ctx, a, []*event.Event{{Source: "x"}})
	if !closeCalled {
		t.Fatal("OnClose was not called")
	}
	// Should have original event + close event
	hasClose := false
	for _, e := range out {
		if e.Source == "close_event" {
			hasClose = true
		}
	}
	if !hasClose {
		t.Fatal("expected close_event in output")
	}
}

func TestNewStatefulAnalyzer_Ticker(t *testing.T) {
	tickCount := 0
	a := transforms.NewStatefulAnalyzer("ticker", transforms.StatefulOpts{
		BufSize:      10,
		TickInterval: 50 * time.Millisecond,
		OnEvent: func(e *event.Event, emit func(*event.Event)) {
			emit(e)
		},
		OnTick: func(emit func(*event.Event)) {
			tickCount++
			emit(&event.Event{Source: "tick"})
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	in := make(chan *event.Event)
	outCh := a.Process(ctx, in)

	// Let ticks accumulate
	time.Sleep(200 * time.Millisecond)
	close(in)

	var out []*event.Event
	for e := range outCh {
		out = append(out, e)
	}

	if tickCount == 0 {
		t.Fatal("expected at least one tick")
	}
	hasTick := false
	for _, e := range out {
		if e.Source == "tick" {
			hasTick = true
		}
	}
	if !hasTick {
		t.Fatal("expected tick event in output")
	}
}

func TestNewStatefulAnalyzer_BufSize(t *testing.T) {
	a := transforms.NewStatefulAnalyzer("buf", transforms.StatefulOpts{
		BufSize: 5,
		OnEvent: func(e *event.Event, emit func(*event.Event)) {
			emit(e)
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	out := runAnalyzer(ctx, a, []*event.Event{{Source: "a"}, {Source: "b"}})
	if len(out) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out))
	}
}
