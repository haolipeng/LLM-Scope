package pipeline

import (
	"context"

	"github.com/haolipeng/LLM-Scope/internal/event"
	pipelinecore "github.com/haolipeng/LLM-Scope/internal/pipeline/core"
	pipelinestream "github.com/haolipeng/LLM-Scope/internal/pipeline/stream"
	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
)

// Pipeline 将数据源、分析器和输出端组织成一条统一的事件处理流水线。
//
// 使用示例:
//
//	pipeline.New().
//	    Sources(
//	        pipeline.WithAnalyzers(sslRunner, sslFilter, httpParser),
//	        processRunner,
//	    ).
//	    Analyzers(securityAnalyzer, toolCallAnalyzer).
//	    Sinks(consoleSink, duckdbSink).
//	    Run(ctx)
type Pipeline struct {
	sources   []pipelinetypes.Runner
	analyzers []pipelinetypes.Analyzer
	sinks     []pipelinetypes.Sink
}

// New 创建一条空的流水线。
func New() *Pipeline {
	return &Pipeline{}
}

// Sources 设置数据源。多个 Source 的事件流在进入 Analyzer 链之前自动合并。
// 可以使用 WithAnalyzers 为单个 Source 绑定专属的预处理 Analyzer。
func (p *Pipeline) Sources(runners ...pipelinetypes.Runner) *Pipeline {
	p.sources = append(p.sources, runners...)
	return p
}

// Analyzers 设置全局分析器链，按顺序串联处理合并后的事件流。
func (p *Pipeline) Analyzers(analyzers ...pipelinetypes.Analyzer) *Pipeline {
	p.analyzers = append(p.analyzers, analyzers...)
	return p
}

// Sinks 设置输出端，以旁路方式并行消费事件（日志、数据库等）。
func (p *Pipeline) Sinks(sinks ...pipelinetypes.Sink) *Pipeline {
	p.sinks = append(p.sinks, sinks...)
	return p
}

// Run 启动所有 Source，将事件流经 Analyzer 链和 Sink，阻塞直到所有流结束或 ctx 取消。
func (p *Pipeline) Run(ctx context.Context) error {
	// 启动所有 Source，收集事件流
	var streams []<-chan *event.Event
	for _, r := range p.sources {
		s, err := r.Run(ctx)
		if err != nil {
			return err
		}
		streams = append(streams, s)
	}

	// 合并所有 Source 的事件流
	var merged <-chan *event.Event
	switch len(streams) {
	case 0:
		ch := make(chan *event.Event)
		close(ch)
		merged = ch
	case 1:
		merged = streams[0]
	default:
		merged = pipelinestream.MergeStreams(ctx, streams...)
	}

	// 组装 Analyzer 链 + Sink
	var stages []pipelinetypes.Analyzer
	stages = append(stages, p.analyzers...)
	if len(p.sinks) > 0 {
		stages = append(stages, pipelinecore.AttachSinks(p.sinks...))
	}

	// 驱动管道
	out := pipelinecore.Chain(stages...).Process(ctx, merged)
	for range out {
		// drain
	}
	return nil
}

// analyzedRunner 将一个 Runner 的输出经过 Analyzer 链处理后再暴露为 Runner。
type analyzedRunner struct {
	inner     pipelinetypes.Runner
	analyzers []pipelinetypes.Analyzer
}

// WithAnalyzers 为一个 Source 绑定专属的预处理 Analyzer 链。
// 返回的 Runner 在 Run 时会先启动原始 Runner，再将事件流经指定的 Analyzer 链处理后输出。
func WithAnalyzers(runner pipelinetypes.Runner, analyzers ...pipelinetypes.Analyzer) pipelinetypes.Runner {
	if len(analyzers) == 0 {
		return runner
	}
	return &analyzedRunner{inner: runner, analyzers: analyzers}
}

func (r *analyzedRunner) ID() string   { return r.inner.ID() }
func (r *analyzedRunner) Name() string { return r.inner.Name() }
func (r *analyzedRunner) Stop() error  { return r.inner.Stop() }

func (r *analyzedRunner) Run(ctx context.Context) (<-chan *event.Event, error) {
	raw, err := r.inner.Run(ctx)
	if err != nil {
		return nil, err
	}
	return pipelinecore.Chain(r.analyzers...).Process(ctx, raw), nil
}
