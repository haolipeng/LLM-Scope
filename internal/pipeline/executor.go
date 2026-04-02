package pipeline

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	pipelinesink "github.com/haolipeng/LLM-Scope/internal/pipeline/sink"
	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
)

// ExecuteConfig 单 Runner 命令的通用执行配置
type ExecuteConfig struct {
	Runner     pipelinetypes.Runner
	Analyzers  []pipelinetypes.Analyzer // Runner 专属 analyzer（如 SSL 的过滤器链）
	Sinks      []pipelinetypes.Sink     // 通用输出端（如落盘/控制台输出）
	LogFile    string
	RotateLogs bool
	MaxLogSize int
	Quiet      bool
	OnSignal   func() // 信号回调（如打印 filter 指标）
}

// Execute 启动 Runner 并驱动 analyzer 管道直到 ctx 结束
func Execute(cfg ExecuteConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if cfg.OnSignal != nil {
			cfg.OnSignal()
		}
		cancel()
	}()

	sinks := append([]pipelinetypes.Sink{}, cfg.Sinks...)
	if cfg.LogFile != "" {
		sinks = append(sinks, pipelinesink.NewFileLogger(cfg.LogFile, cfg.RotateLogs, cfg.MaxLogSize))
	}
	if !cfg.Quiet {
		sinks = append(sinks, pipelinesink.NewOutput())
	}

	events, err := cfg.Runner.Run(ctx)
	if err != nil {
		return err
	}

	p := New().WithTransforms(cfg.Analyzers...).WithSinks(sinks...)
	p.Drain(ctx, events, nil)
	return nil
}
