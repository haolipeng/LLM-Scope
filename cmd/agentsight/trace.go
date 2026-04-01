package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	agentsightserver "github.com/haolipeng/LLM-Scope/internal/interfaces/http"
	interfacesink "github.com/haolipeng/LLM-Scope/internal/interfaces/sink"
	"github.com/haolipeng/LLM-Scope/internal/pipeline"
	pipelinecore "github.com/haolipeng/LLM-Scope/internal/pipeline/core"
	pipelinestream "github.com/haolipeng/LLM-Scope/internal/pipeline/stream"
	pipelinetransforms "github.com/haolipeng/LLM-Scope/internal/pipeline/transforms"
	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	processcollector "github.com/haolipeng/LLM-Scope/internal/runtime/collectors/process"
	sslcollector "github.com/haolipeng/LLM-Scope/internal/runtime/collectors/ssl"
	stdiocollector "github.com/haolipeng/LLM-Scope/internal/runtime/collectors/stdio"
	systemcollector "github.com/haolipeng/LLM-Scope/internal/runtime/collectors/system"
	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
	"github.com/spf13/cobra"
)

// OutputConfig 输出和服务器配置
type OutputConfig struct {
	Server     bool
	ServerPort int
	LogFile    string
	Quiet      bool
	RotateLogs bool
	MaxLogSize int
}

// TraceSSLConfig SSL 监控专用配置
type TraceSSLConfig struct {
	Enabled     bool
	UID         int
	Filter      []string
	Handshake   bool
	HTTP        bool
	Raw         bool
	HTTPFilter  []string
	DisableAuth bool
	BinaryPath  string
}

// TraceProcessConfig 进程监控专用配置
type TraceProcessConfig struct {
	Enabled  bool
	Duration int
	Mode     int
}

// TraceSystemConfig 系统监控专用配置
type TraceSystemConfig struct {
	Enabled  bool
	Interval int
}

// TraceStdioConfig Stdio 监控专用配置
type TraceStdioConfig struct {
	Enabled  bool
	UID      int
	Comm     string
	AllFDs   bool
	MaxBytes int
}

// TraceConfig 综合监控配置（嵌套子配置）
type TraceConfig struct {
	Comm    string
	PID     int
	SSL     TraceSSLConfig
	Process TraceProcessConfig
	System  TraceSystemConfig
	Stdio   TraceStdioConfig
	Output  OutputConfig
}

var (
	traceSSL            bool
	traceProcess        bool
	traceSystem         bool
	traceStdio          bool
	traceComm           string
	tracePID            int
	traceSSLUID         int
	traceSSLFilter      []string
	traceSSLHandshake   bool
	traceSSLHTTP        bool
	traceSSLRaw         bool
	traceHTTPFilter     []string
	traceDisableAuth    bool
	traceDuration       int
	traceMode           int
	traceSystemInterval int
	traceBinaryPath     string
	traceStdioUID       int
	traceStdioComm      string
	traceStdioAllFDs    bool
	traceStdioMaxBytes  int
)

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "综合监控",
	Run:   runTrace,
}

func init() {
	rootCmd.AddCommand(traceCmd)

	traceCmd.Flags().BoolVar(&traceSSL, "ssl", true, "启用 SSL 监控")
	traceCmd.Flags().BoolVar(&traceProcess, "process", true, "启用进程监控")
	traceCmd.Flags().BoolVar(&traceSystem, "system", false, "启用系统监控")
	traceCmd.Flags().StringVarP(&traceComm, "comm", "c", "", "进程名过滤(逗号分隔)")
	traceCmd.Flags().IntVarP(&tracePID, "pid", "p", 0, "PID 过滤")
	traceCmd.Flags().IntVar(&traceSSLUID, "ssl-uid", 0, "SSL UID 过滤")
	traceCmd.Flags().StringArrayVar(&traceSSLFilter, "ssl-filter", nil, "SSL 过滤表达式")
	traceCmd.Flags().BoolVar(&traceSSLHandshake, "ssl-handshake", false, "显示握手事件")
	traceCmd.Flags().BoolVar(&traceSSLHTTP, "ssl-http", true, "启用 HTTP 解析")
	traceCmd.Flags().BoolVar(&traceSSLRaw, "ssl-raw-data", false, "包含原始数据")
	traceCmd.Flags().StringArrayVar(&traceHTTPFilter, "http-filter", nil, "HTTP 过滤表达式")
	traceCmd.Flags().BoolVar(&traceDisableAuth, "disable-auth-removal", false, "禁用敏感头移除")
	traceCmd.Flags().IntVar(&traceDuration, "duration", 0, "最小进程持续时间(毫秒)")
	traceCmd.Flags().IntVar(&traceMode, "mode", 0, "进程过滤模式")
	traceCmd.Flags().IntVar(&traceSystemInterval, "system-interval", 10, "系统监控间隔(秒)")
	traceCmd.Flags().StringVar(&traceBinaryPath, "binary-path", "", "SSL 库二进制路径")
	traceCmd.Flags().BoolVar(&traceStdio, "stdio", false, "启用 stdio 监控 (需要 --pid)")
	traceCmd.Flags().IntVar(&traceStdioUID, "stdio-uid", 0, "stdio UID 过滤")
	traceCmd.Flags().StringVar(&traceStdioComm, "stdio-comm", "", "stdio 进程名过滤")
	traceCmd.Flags().BoolVar(&traceStdioAllFDs, "stdio-all-fds", false, "捕获所有 FD")
	traceCmd.Flags().IntVar(&traceStdioMaxBytes, "stdio-max-bytes", 8192, "stdio 每事件最大字节数")
}

// runTrace 从命令行标志构建 TraceConfig 并启动综合监控
func runTrace(cmd *cobra.Command, _ []string) {
	cfg := TraceConfig{
		Comm: traceComm,
		PID:  tracePID,
		SSL: TraceSSLConfig{
			Enabled:     traceSSL,
			UID:         traceSSLUID,
			Filter:      traceSSLFilter,
			Handshake:   traceSSLHandshake,
			HTTP:        traceSSLHTTP,
			Raw:         traceSSLRaw,
			HTTPFilter:  traceHTTPFilter,
			DisableAuth: traceDisableAuth,
			BinaryPath:  traceBinaryPath,
		},
		Process: TraceProcessConfig{
			Enabled:  traceProcess,
			Duration: traceDuration,
			Mode:     traceMode,
		},
		System: TraceSystemConfig{
			Enabled:  traceSystem,
			Interval: traceSystemInterval,
		},
		Stdio: TraceStdioConfig{
			Enabled:  traceStdio,
			UID:      traceStdioUID,
			Comm:     traceStdioComm,
			AllFDs:   traceStdioAllFDs,
			MaxBytes: traceStdioMaxBytes,
		},
		Output: OutputConfig{
			Server:     server,
			ServerPort: serverPort,
			LogFile:    logFile,
			Quiet:      quiet,
			RotateLogs: rotateLogs,
			MaxLogSize: maxLogSize,
		},
	}
	executeTrace(cmd, cfg)
}

// executeTrace 根据配置启动各 runner 和 analyzer 管道
func executeTrace(cmd *cobra.Command, cfg TraceConfig) {
	if !cfg.SSL.Enabled && !cfg.Process.Enabled && !cfg.System.Enabled && !cfg.Stdio.Enabled {
		cmd.PrintErrln("至少启用一种监控类型 (--ssl/--process/--system/--stdio)")
		os.Exit(1)
	}

	if cfg.Stdio.Enabled && cfg.PID == 0 {
		cmd.PrintErrln("--stdio 需要指定 --pid")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// allAnalyzers 收集所有 analyzer 实例，用于信号回调中上报指标
	var allAnalyzers []pipelinetypes.Analyzer

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh // 收到信号后，打印所有 analyzer 的指标
		for _, a := range allAnalyzers {
			if r, ok := a.(pipelinetypes.MetricsReporter); ok {
				r.ReportMetrics()
			}
		}
		cancel()
	}()

	var runners []pipelinetypes.Runner
	var streams []<-chan *runtimeevent.Event

	// 构建 SSL 监控管道：过滤器 -> SSE 合并 -> HTTP 解析 -> 认证头移除
	if cfg.SSL.Enabled {
		sslConfig := sslcollector.Config{
			PID:        cfg.PID,
			UID:        cfg.SSL.UID,
			Comm:       cfg.Comm,
			BinaryPath: cfg.SSL.BinaryPath,
			OpenSSL:    true,
			Handshake:  cfg.SSL.Handshake,
		}

		sslRunner := sslcollector.New(sslConfig)

		sslAnalyzers := []pipelinetypes.Analyzer{}
		if len(cfg.SSL.Filter) > 0 {
			sslAnalyzers = append(sslAnalyzers, pipelinetransforms.NewSSLFilter(cfg.SSL.Filter))
		}
		if cfg.SSL.HTTP {
			sslAnalyzers = append(sslAnalyzers, pipelinetransforms.NewSSEMerger())
			sslAnalyzers = append(sslAnalyzers, pipelinetransforms.NewHTTPParser(cfg.SSL.Raw))
			if len(cfg.SSL.HTTPFilter) > 0 {
				sslAnalyzers = append(sslAnalyzers, pipelinetransforms.NewHTTPFilter(cfg.SSL.HTTPFilter))
			}
			if !cfg.SSL.DisableAuth {
				sslAnalyzers = append(sslAnalyzers, pipelinetransforms.NewAuthRemover())
			}
		}

		allAnalyzers = append(allAnalyzers, sslAnalyzers...)

		events, err := sslRunner.Run(ctx)
		if err != nil {
			cmd.PrintErrf("启动 SSL 监控失败: %v\n", err)
			os.Exit(1)
		}
		sslStream := pipelinecore.Chain(sslAnalyzers...).Process(ctx, events)
		streams = append(streams, sslStream)
	}

	if cfg.Process.Enabled {
		procConfig := processcollector.Config{
			MinDurationMs: int64(cfg.Process.Duration),
			PID:           cfg.PID,
			FilterMode:    cfg.Process.Mode,
		}
		if cfg.Comm != "" {
			procConfig.Commands = splitComm(cfg.Comm)
		}

		procRunner := processcollector.New(procConfig)
		runners = append(runners, procRunner)
	}

	if cfg.System.Enabled {
		sysRunner := systemcollector.New(systemcollector.Config{
			IntervalSeconds: cfg.System.Interval,
			PID:             cfg.PID,
			Comm:            cfg.Comm,
			IncludeChildren: true,
		})
		runners = append(runners, sysRunner)
	}

	if cfg.Stdio.Enabled {
		stdioRunner := stdiocollector.New(stdiocollector.Config{
			PID:      cfg.PID,
			UID:      cfg.Stdio.UID,
			Comm:     cfg.Stdio.Comm,
			AllFDs:   cfg.Stdio.AllFDs,
			MaxBytes: cfg.Stdio.MaxBytes,
		})
		runners = append(runners, stdioRunner)
	}

	// 合并所有 runner 输出并构建全局分析管道
	combined := pipelinestream.NewCombinedRunner(runners...)
	combinedStream, err := combined.Run(ctx)
	if err != nil {
		cmd.PrintErrf("启动监控失败: %v\n", err)
		os.Exit(1)
	}
	merged := pipelinestream.MergeStreams(ctx, append(streams, combinedStream)...)

	eventHub := agentsightserver.NewEventHub(cfg.Output.LogFile)
	if cfg.Output.Server {
		startServer(ctx, eventHub, cfg.Output.ServerPort)
	}

	// 全局处理管道：transform + sinks
	var transforms []pipelinetypes.Analyzer
	transforms = append(transforms, pipelinetransforms.NewToolCallAggregator())

	var sinks []pipelinetypes.Sink
	if cfg.Output.LogFile != "" {
		sinks = append(sinks, interfacesink.NewFileLogger(cfg.Output.LogFile, cfg.Output.RotateLogs, cfg.Output.MaxLogSize))
	}
	if !cfg.Output.Quiet {
		sinks = append(sinks, interfacesink.NewOutput())
	}

	// 消费全局管道输出，转发到 eventHub 供 WebSocket 推送
	p := pipeline.New().WithTransforms(transforms...).WithSinks(sinks...)
	p.Drain(ctx, merged, func(event *runtimeevent.Event) {
		if cfg.Output.Server {
			eventHub.Publish(event)
		}
	})
}

// startServer 启动 HTTP 服务器并注册优雅关闭
func startServer(ctx context.Context, hub *agentsightserver.EventHub, port int) {
	assets := agentsightserver.WebAssets()
	router := agentsightserver.SetupRouter(assets, hub)
	addr := fmt.Sprintf(":%d", port)

	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Web 服务器启动失败: %v\n", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Web 服务器关闭失败: %v\n", err)
		}
	}()
}

// splitComm splits a comma-separated command list into a string slice.
func splitComm(comm string) []string {
	var result []string
	for _, s := range strings.Split(comm, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}
