package types

import (
	"context"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

// Analyzer 处理输入事件流，并输出变换后的事件流。
type Analyzer interface {
	Name() string
	Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event
}

// Sink 只消费事件用于副作用处理（如日志、导出），不会继续输出事件。
type Sink interface {
	Name() string
	Consume(ctx context.Context, in <-chan *event.Event)
}

// MetricsReporter 可选接口，支持过滤指标上报的 Analyzer 实现此接口。
type MetricsReporter interface {
	ReportMetrics()
}

// Runner 从数据源（如 eBPF、/proc）中产生事件流。
type Runner interface {
	ID() string
	Name() string
	Run(ctx context.Context) (<-chan *event.Event, error)
	Stop() error
}
