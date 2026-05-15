package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	processcollector "github.com/haolipeng/LLM-Scope/internal/collectors/process"
	sslcollector "github.com/haolipeng/LLM-Scope/internal/collectors/ssl"
	stdiocollector "github.com/haolipeng/LLM-Scope/internal/collectors/stdio"
	systemcollector "github.com/haolipeng/LLM-Scope/internal/collectors/system"
	agentsightserver "github.com/haolipeng/LLM-Scope/internal/httpserver"
	"github.com/haolipeng/LLM-Scope/internal/logging"
	"github.com/haolipeng/LLM-Scope/internal/pipeline"
	pipelinecore "github.com/haolipeng/LLM-Scope/internal/pipeline/core"
	pipelinesink "github.com/haolipeng/LLM-Scope/internal/pipeline/sink"
	pipelinestream "github.com/haolipeng/LLM-Scope/internal/pipeline/stream"
	pipelinetransforms "github.com/haolipeng/LLM-Scope/internal/pipeline/transforms"
	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// OutputConfig 输出和服务器配置
type OutputConfig struct {
	Server     bool
	ServerPort int
	LogFile    string
	Quiet      bool
	RotateLogs bool
	MaxLogSize int
	DuckDBPath string // DuckDB 文件路径，空则不启用
}

// TraceSSLConfig SSL 监控专用配置（默认启用）
type TraceSSLConfig struct {
	UID         int
	Filter      []string
	Handshake   bool
	Raw         bool
	HTTPFilter  []string
	DisableAuth bool
	BinaryPath  string
	// HTTPPCapPath 非空时，在 HTTP 解析后、HTTP 过滤前将明文 HTTP 写入合成 TCP 的 pcap（Wireshark 可读）
	HTTPPCapPath string
}

// TraceProcessConfig 进程监控专用配置（默认启用）
type TraceProcessConfig struct {
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
	traceSystem         bool
	traceStdio          bool
	traceComm           string
	tracePID            int
	traceSSLUID         int
	traceSSLFilter      []string
	traceSSLHandshake   bool
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
	traceDuckDBPath     string
	traceHTTPPCap string
)

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "综合监控",
	Run:   runTrace,
}

func init() {
	rootCmd.AddCommand(traceCmd)

	traceCmd.Flags().BoolVar(&traceSystem, "system", false, "启用系统监控")
	traceCmd.Flags().StringVarP(&traceComm, "comm", "c", "", "进程名过滤(逗号分隔)")
	traceCmd.Flags().IntVarP(&tracePID, "pid", "p", 0, "PID 过滤")
	traceCmd.Flags().IntVar(&traceSSLUID, "ssl-uid", 0, "SSL UID 过滤")
	traceCmd.Flags().StringArrayVar(&traceSSLFilter, "ssl-filter", nil, "SSL 过滤表达式")
	traceCmd.Flags().BoolVar(&traceSSLHandshake, "ssl-handshake", false, "显示握手事件")
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
	traceCmd.Flags().StringVar(&traceDuckDBPath, "duckdb-path", "", "DuckDB 数据库文件路径（空则不启用）")
	traceCmd.Flags().StringVar(&traceHTTPPCap, "http-pcap", "", "将 SSE 合并后解析的 HTTP 写入合成 TCP 的 pcap 文件路径（空则关闭）")
}

// runTrace 从命令行标志构建 TraceConfig 并启动综合监控
func runTrace(cmd *cobra.Command, _ []string) {
	cfg := TraceConfig{
		Comm: traceComm,
		PID:  tracePID,
		SSL: TraceSSLConfig{
			UID:          traceSSLUID,
			Filter:       traceSSLFilter,
			Handshake:    traceSSLHandshake,
			Raw:          traceSSLRaw,
			HTTPFilter:   traceHTTPFilter,
			DisableAuth:  traceDisableAuth,
			BinaryPath:   traceBinaryPath,
			HTTPPCapPath: traceHTTPPCap,
		},
		Process: TraceProcessConfig{
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
			DuckDBPath: traceDuckDBPath,
		},
	}
	executeTrace(cmd, cfg)
}

// validateTraceConfig 检查配置的前置约束
func validateTraceConfig(cmd *cobra.Command, cfg TraceConfig) {
	if cfg.Stdio.Enabled && cfg.PID == 0 {
		cliErrln(cmd, "--stdio 需要指定 --pid")
		os.Exit(1)
	}
}

// SSLPipelineConfig 描述 SSL 分析管道的构建参数（trace 和 ssl 命令共用）
type SSLPipelineConfig struct {
	SSLFilters  []string
	HTTPRaw     bool
	HTTPPCap    string
	HTTPFilters []string
	DisableAuth bool
}

// buildSSLAnalyzerChain 构建 SSL 分析器链：SSL 过滤 → SSE 合并 → HTTP 解析 → pcap → HTTP 过滤 → 认证头移除
func buildSSLAnalyzerChain(cmd *cobra.Command, sslCfg SSLPipelineConfig) []pipelinetypes.Analyzer {
	var analyzers []pipelinetypes.Analyzer
	if len(sslCfg.SSLFilters) > 0 {
		analyzers = append(analyzers, pipelinetransforms.NewSSLFilter(sslCfg.SSLFilters))
	}
	analyzers = append(analyzers, pipelinetransforms.NewSSEMerger())
	// When writing pcap, force raw data inclusion so payloads stay faithful.
	includeRaw := sslCfg.HTTPRaw || sslCfg.HTTPPCap != ""
	analyzers = append(analyzers, pipelinetransforms.NewHTTPParser(includeRaw))
	if sslCfg.HTTPPCap != "" {
		pcapW, err := pipelinetransforms.NewHTTPPCAPWriter(sslCfg.HTTPPCap)
		if err != nil {
			cliErrf(cmd, "HTTP pcap: %v\n", err)
			os.Exit(1)
		}
		if pcapW != nil {
			analyzers = append(analyzers, pcapW)
		}
	}
	if len(sslCfg.HTTPFilters) > 0 {
		analyzers = append(analyzers, pipelinetransforms.NewHTTPFilter(sslCfg.HTTPFilters))
	}
	if !sslCfg.DisableAuth {
		analyzers = append(analyzers, pipelinetransforms.NewAuthRemover())
	}
	return analyzers
}

// buildRunners 根据配置构建 process/system/stdio runner 列表
// Process 总是启用；System 和 Stdio 由 Enabled 字段控制。
func buildRunners(cfg TraceConfig) []pipelinetypes.Runner {
	procConfig := processcollector.Config{
		MinDurationMs: int64(cfg.Process.Duration),
		PID:           cfg.PID,
		FilterMode:    cfg.Process.Mode,
	}
	if cfg.Comm != "" {
		procConfig.Commands = splitComm(cfg.Comm)
	}
	runners := []pipelinetypes.Runner{processcollector.New(procConfig)}
	if cfg.System.Enabled {
		runners = append(runners, systemcollector.New(systemcollector.Config{
			IntervalSeconds: cfg.System.Interval,
			PID:             cfg.PID,
			Comm:            cfg.Comm,
			IncludeChildren: true,
		}))
	}
	if cfg.Stdio.Enabled {
		runners = append(runners, stdiocollector.New(stdiocollector.Config{
			PID:      cfg.PID,
			UID:      cfg.Stdio.UID,
			Comm:     cfg.Stdio.Comm,
			AllFDs:   cfg.Stdio.AllFDs,
			MaxBytes: cfg.Stdio.MaxBytes,
		}))
	}
	return runners
}

// buildSinks 构建输出 sink 列表和可选的 analytics DB 连接
func buildSinks(cmd *cobra.Command, cfg TraceConfig) ([]pipelinetypes.Sink, *sql.DB) {
	var sinks []pipelinetypes.Sink
	var analyticsDB *sql.DB
	if cfg.Output.DuckDBPath != "" {
		duckdbSink, err := pipelinesink.NewDuckDBSink(pipelinesink.DuckDBConfig{
			DBPath:     cfg.Output.DuckDBPath,
			CommFilter: cfg.Comm,
			BinaryPath: cfg.SSL.BinaryPath,
		})
		if err != nil {
			cliErrf(cmd, "启动 DuckDB 失败: %v\n", err)
			os.Exit(1)
		}
		sinks = append(sinks, duckdbSink)
		analyticsDB = duckdbSink.DB()
	}
	if cfg.Output.LogFile != "" {
		sinks = append(sinks, pipelinesink.NewFileLogger(cfg.Output.LogFile, cfg.Output.RotateLogs, cfg.Output.MaxLogSize))
	}
	if !cfg.Output.Quiet {
		sinks = append(sinks, pipelinesink.NewOutput())
	}
	return sinks, analyticsDB
}

// buildGlobalTransforms 构建全局分析管道的 transform 列表
func buildGlobalTransforms(sslEnabled bool) []pipelinetypes.Analyzer {
	transforms := []pipelinetypes.Analyzer{pipelinetransforms.NewSecurityAnalyzer()}
	if sslEnabled {
		transforms = append(transforms, pipelinetransforms.NewClaudeToolCallAnalyzer())
	} else {
		transforms = append(transforms, pipelinetransforms.NewToolCallAggregator())
	}
	return transforms
}

// executeTrace 根据配置启动各 runner 和 analyzer 管道
func executeTrace(cmd *cobra.Command, cfg TraceConfig) {
	validateTraceConfig(cmd, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := logging.Init(logging.Config{
		EventLogPath: cfg.Output.LogFile,
		Rotate:       cfg.Output.RotateLogs,
		MaxSizeMB:    cfg.Output.MaxLogSize,
		Quiet:        cfg.Output.Quiet,
	}); err != nil {
		cliErrf(cmd, "应用日志初始化失败: %v\n", err)
		os.Exit(1)
	}
	defer logging.Sync()

	// SSL 监控管道（默认启用）
	sslAnalyzers := buildSSLAnalyzerChain(cmd, SSLPipelineConfig{
		SSLFilters:  cfg.SSL.Filter,
		HTTPRaw:     cfg.SSL.Raw,
		HTTPPCap:    cfg.SSL.HTTPPCapPath,
		HTTPFilters: cfg.SSL.HTTPFilter,
		DisableAuth: cfg.SSL.DisableAuth,
	})
	allAnalyzers := sslAnalyzers

	sslRunner := sslcollector.New(sslcollector.Config{
		PID: cfg.PID, UID: cfg.SSL.UID, Comm: cfg.Comm,
		BinaryPath: cfg.SSL.BinaryPath, OpenSSL: true, Handshake: cfg.SSL.Handshake,
	})
	sslEvents, err := sslRunner.Run(ctx)
	if err != nil {
		cliErrf(cmd, "启动 SSL 监控失败: %v\n", err)
		os.Exit(1)
	}
	sslStream := pipelinecore.Chain(sslAnalyzers...).Process(ctx, sslEvents)

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		for _, a := range allAnalyzers {
			if r, ok := a.(pipelinetypes.MetricsReporter); ok {
				r.ReportMetrics()
			}
		}
		cancel()
	}()

	// 合并 runner 输出
	runners := buildRunners(cfg)
	combined := pipelinestream.NewCombinedRunner(runners...)
	combinedStream, err := combined.Run(ctx)
	if err != nil {
		cliErrf(cmd, "启动监控失败: %v\n", err)
		os.Exit(1)
	}
	merged := pipelinestream.MergeStreams(ctx, sslStream, combinedStream)

	// Sink 和 Server
	sinks, analyticsDB := buildSinks(cmd, cfg)
	if cfg.Output.Server {
		startServer(ctx, cfg.Output.ServerPort, analyticsDB)
	}

	// 全局管道（SSL 总是启用，始终使用 ClaudeToolCallAnalyzer）
	transforms := buildGlobalTransforms(true)
	p := pipeline.New().WithTransforms(transforms...).WithSinks(sinks...)
	p.Drain(ctx, merged, nil)
}

// startServer 启动 HTTP 服务器并注册优雅关闭
func startServer(ctx context.Context, port int, analyticsDB *sql.DB) {
	assets := agentsightserver.WebAssets()
	router := agentsightserver.SetupRouter(assets, analyticsDB)
	addr := fmt.Sprintf(":%d", port)

	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.NamedZap("web").Error("Web 服务器启动失败", zap.Error(err))
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logging.NamedZap("web").Error("Web 服务器关闭失败", zap.Error(err))
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
