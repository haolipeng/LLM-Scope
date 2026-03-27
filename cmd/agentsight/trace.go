package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/haolipeng/LLM-Scope/internal/analyzer"
	"github.com/haolipeng/LLM-Scope/internal/runner"
	agentsightserver "github.com/haolipeng/LLM-Scope/internal/server"
	"github.com/spf13/cobra"
)

// TraceConfig holds all configuration for a trace session.
type TraceConfig struct {
	// 监控开关
	SSL     bool
	Process bool
	System  bool
	Stdio   bool

	// 通用过滤
	Comm string
	PID  int

	// SSL 相关
	SSLUID       int
	SSLFilter    []string
	SSLHandshake bool
	SSLHTTP      bool
	SSLRaw       bool
	HTTPFilter   []string
	DisableAuth  bool
	BinaryPath   string

	// Process 相关
	Duration int
	Mode     int

	// System 相关
	SystemInterval int

	// Stdio 相关
	StdioUID      int
	StdioComm     string
	StdioAllFDs   bool
	StdioMaxBytes int

	// 输出相关
	Server     bool
	ServerPort int
	LogFile    string
	Quiet      bool
	RotateLogs bool
	MaxLogSize int
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

func runTrace(cmd *cobra.Command, _ []string) {
	cfg := TraceConfig{
		SSL:            traceSSL,
		Process:        traceProcess,
		System:         traceSystem,
		Stdio:          traceStdio,
		Comm:           traceComm,
		PID:            tracePID,
		SSLUID:         traceSSLUID,
		SSLFilter:      traceSSLFilter,
		SSLHandshake:   traceSSLHandshake,
		SSLHTTP:        traceSSLHTTP,
		SSLRaw:         traceSSLRaw,
		HTTPFilter:     traceHTTPFilter,
		DisableAuth:    traceDisableAuth,
		Duration:       traceDuration,
		Mode:           traceMode,
		SystemInterval: traceSystemInterval,
		BinaryPath:     traceBinaryPath,
		StdioUID:       traceStdioUID,
		StdioComm:      traceStdioComm,
		StdioAllFDs:    traceStdioAllFDs,
		StdioMaxBytes:  traceStdioMaxBytes,
		Server:         server,
		ServerPort:     serverPort,
		LogFile:        logFile,
		Quiet:          quiet,
		RotateLogs:     rotateLogs,
		MaxLogSize:     maxLogSize,
	}
	executeTrace(cmd, cfg)
}

func executeTrace(cmd *cobra.Command, cfg TraceConfig) {
	if !cfg.SSL && !cfg.Process && !cfg.System && !cfg.Stdio {
		cmd.PrintErrln("至少启用一种监控类型 (--ssl/--process/--system/--stdio)")
		os.Exit(1)
	}

	if cfg.Stdio && cfg.PID == 0 {
		cmd.PrintErrln("--stdio 需要指定 --pid")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		analyzer.PrintGlobalHTTPFilterMetrics()
		analyzer.PrintGlobalSSLFilterMetrics()
		cancel()
	}()

	var runners []runner.Runner

	if cfg.SSL {
		sslArgs := buildSSLArgs(cfg)
		sslRunner := runner.NewSSLRunner(runner.SSLConfig{
			Args: sslArgs,
		})

		sslAnalyzers := []analyzer.Analyzer{}
		if len(cfg.SSLFilter) > 0 {
			sslAnalyzers = append(sslAnalyzers, analyzer.NewSSLFilter(cfg.SSLFilter))
		}
		if cfg.SSLHTTP {
			sslAnalyzers = append(sslAnalyzers, analyzer.NewSSEMerger())
			sslAnalyzers = append(sslAnalyzers, analyzer.NewHTTPParser(cfg.SSLRaw))
			if len(cfg.HTTPFilter) > 0 {
				sslAnalyzers = append(sslAnalyzers, analyzer.NewHTTPFilter(cfg.HTTPFilter))
			}
			if !cfg.DisableAuth {
				sslAnalyzers = append(sslAnalyzers, analyzer.NewAuthRemover())
			}
		}

		events, err := sslRunner.Run(ctx)
		if err != nil {
			cmd.PrintErrf("启动 SSL 监控失败: %v\n", err)
			os.Exit(1)
		}
		sslStream := analyzer.Chain(sslAnalyzers...).Process(ctx, events)
		runners = append(runners, runner.FromChannel("ssl", sslStream))
	}

	if cfg.Process {
		procArgs := buildProcessArgs(cfg)
		procRunner := runner.NewProcessRunner(runner.ProcessConfig{Args: procArgs})
		events, err := procRunner.Run(ctx)
		if err != nil {
			cmd.PrintErrf("启动进程监控失败: %v\n", err)
			os.Exit(1)
		}
		runners = append(runners, runner.FromChannel("process", events))
	}

	if cfg.System {
		sysRunner := runner.NewSystemRunner(runner.SystemConfig{
			IntervalSeconds: cfg.SystemInterval,
			PID:             cfg.PID,
			Comm:            cfg.Comm,
			IncludeChildren: true,
		})
		events, err := sysRunner.Run(ctx)
		if err != nil {
			cmd.PrintErrf("启动系统监控失败: %v\n", err)
			os.Exit(1)
		}
		runners = append(runners, runner.FromChannel("system", events))
	}

	if cfg.Stdio {
		stdioRunner := runner.NewStdioRunner(runner.StdioConfig{
			PID:      cfg.PID,
			UID:      cfg.StdioUID,
			Comm:     cfg.StdioComm,
			AllFDs:   cfg.StdioAllFDs,
			MaxBytes: cfg.StdioMaxBytes,
		})
		events, err := stdioRunner.Run(ctx)
		if err != nil {
			cmd.PrintErrf("启动 stdio 监控失败: %v\n", err)
			os.Exit(1)
		}
		runners = append(runners, runner.FromChannel("stdio", events))
	}

	combined := runner.NewCombinedRunner(runners...)
	merged, err := combined.Run(ctx)
	if err != nil {
		cmd.PrintErrf("启动监控失败: %v\n", err)
		os.Exit(1)
	}

	eventHub := agentsightserver.NewEventHub(cfg.LogFile)
	if cfg.Server {
		startServer(eventHub, cfg.ServerPort)
	}

	var analyzers []analyzer.Analyzer
	analyzers = append(analyzers, analyzer.NewToolCallAggregator())
	if cfg.LogFile != "" {
		analyzers = append(analyzers, analyzer.NewFileLogger(cfg.LogFile, cfg.RotateLogs, cfg.MaxLogSize))
	}
	if !cfg.Quiet {
		analyzers = append(analyzers, analyzer.NewOutput())
	}

	out := analyzer.Chain(analyzers...).Process(ctx, merged)
	for event := range out {
		if cfg.Server {
			eventHub.Publish(event)
		}
	}
}

func startServer(hub *agentsightserver.EventHub, port int) {
	assets := agentsightserver.WebAssets()
	router := agentsightserver.SetupRouter(assets, hub)
	addr := fmt.Sprintf(":%d", port)
	go func() {
		_ = router.Run(addr)
	}()
}

func buildSSLArgs(cfg TraceConfig) []string {
	var args []string
	if cfg.PID != 0 {
		args = append(args, "-p", fmt.Sprintf("%d", cfg.PID))
	}
	if cfg.SSLUID != 0 {
		args = append(args, "-u", fmt.Sprintf("%d", cfg.SSLUID))
	}
	if cfg.Comm != "" && cfg.BinaryPath == "" {
		args = append(args, "-c", cfg.Comm)
	}
	if cfg.SSLHandshake {
		args = append(args, "--handshake")
	}
	if cfg.BinaryPath != "" {
		args = append(args, "--binary-path", cfg.BinaryPath)
	}
	return args
}

func buildProcessArgs(cfg TraceConfig) []string {
	var args []string
	if cfg.Comm != "" {
		args = append(args, "-c", cfg.Comm)
	}
	if cfg.PID != 0 {
		args = append(args, "-p", fmt.Sprintf("%d", cfg.PID))
	}
	if cfg.Duration > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", cfg.Duration))
	}
	if cfg.Mode > 0 {
		args = append(args, "-m", fmt.Sprintf("%d", cfg.Mode))
	}
	return args
}
