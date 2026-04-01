package pipeline

import (
	"context"

	pipelinecore "github.com/haolipeng/LLM-Scope/internal/pipeline/core"
	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// Pipeline 将变换器和输出端组织成一条统一的事件处理流水线。
type Pipeline struct {
	transforms []pipelinetypes.Analyzer
	sinks      []pipelinetypes.Sink
}

// New 创建一条空的流水线。
func New() *Pipeline {
	return &Pipeline{}
}

// WithTransforms 追加变换阶段。
func (p *Pipeline) WithTransforms(transforms ...pipelinetypes.Analyzer) *Pipeline {
	p.transforms = append(p.transforms, transforms...)
	return p
}

// WithSinks 追加输出阶段。
func (p *Pipeline) WithSinks(sinks ...pipelinetypes.Sink) *Pipeline {
	p.sinks = append(p.sinks, sinks...)
	return p
}

// Process 将配置好的变换器和输出端连接到输入事件流上。
func (p *Pipeline) Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event {
	stages := append([]pipelinetypes.Analyzer{}, p.transforms...)
	if len(p.sinks) > 0 {
		stages = append(stages, pipelinecore.AttachSinks(p.sinks...))
	}
	return pipelinecore.Chain(stages...).Process(ctx, in)
}

// Drain 持续消费处理后的输出，直到流结束或上下文取消。
func (p *Pipeline) Drain(ctx context.Context, in <-chan *runtimeevent.Event, fn func(*runtimeevent.Event)) {
	out := p.Process(ctx, in)
	for event := range out {
		if fn != nil {
			fn(event)
		}
	}
}

