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
	if !traceSSL && !traceProcess && !traceSystem && !traceStdio {
		cmd.PrintErrln("至少启用一种监控类型 (--ssl/--process/--system/--stdio)")
		os.Exit(1)
	}

	if traceStdio && tracePID == 0 {
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

	if traceSSL {
		sslArgs := buildSSLArgs()
		sslRunner := runner.NewSSLRunner(runner.SSLConfig{
			Args: sslArgs,
		})

		sslAnalyzers := []analyzer.Analyzer{}
		if len(traceSSLFilter) > 0 {
			sslAnalyzers = append(sslAnalyzers, analyzer.NewSSLFilter(traceSSLFilter))
		}
		if traceSSLHTTP {
			sslAnalyzers = append(sslAnalyzers, analyzer.NewSSEMerger())
			sslAnalyzers = append(sslAnalyzers, analyzer.NewHTTPParser(traceSSLRaw))
			if len(traceHTTPFilter) > 0 {
				sslAnalyzers = append(sslAnalyzers, analyzer.NewHTTPFilter(traceHTTPFilter))
			}
			if !traceDisableAuth {
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

	if traceProcess {
		procArgs := buildProcessArgs()
		procRunner := runner.NewProcessRunner(runner.ProcessConfig{Args: procArgs})
		events, err := procRunner.Run(ctx)
		if err != nil {
			cmd.PrintErrf("启动进程监控失败: %v\n", err)
			os.Exit(1)
		}
		runners = append(runners, runner.FromChannel("process", events))
	}

	if traceSystem {
		sysRunner := runner.NewSystemRunner(runner.SystemConfig{
			IntervalSeconds: traceSystemInterval,
			PID:             tracePID,
			Comm:            traceComm,
			IncludeChildren: true,
		})
		events, err := sysRunner.Run(ctx)
		if err != nil {
			cmd.PrintErrf("启动系统监控失败: %v\n", err)
			os.Exit(1)
		}
		runners = append(runners, runner.FromChannel("system", events))
	}

	if traceStdio {
		stdioRunner := runner.NewStdioRunner(runner.StdioConfig{
			PID:      tracePID,
			UID:      traceStdioUID,
			Comm:     traceStdioComm,
			AllFDs:   traceStdioAllFDs,
			MaxBytes: traceStdioMaxBytes,
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

	eventHub := agentsightserver.NewEventHub(logFile)
	if server {
		startServer(eventHub)
	}

	var analyzers []analyzer.Analyzer
	analyzers = append(analyzers, analyzer.NewToolCallAggregator())
	if logFile != "" {
		analyzers = append(analyzers, analyzer.NewFileLogger(logFile, rotateLogs, maxLogSize))
	}
	if !quiet {
		analyzers = append(analyzers, analyzer.NewOutput())
	}

	out := analyzer.Chain(analyzers...).Process(ctx, merged)
	for event := range out {
		if server {
			eventHub.Publish(event)
		}
	}
}

func startServer(hub *agentsightserver.EventHub) {
	assets := agentsightserver.WebAssets()
	router := agentsightserver.SetupRouter(assets, hub)
	addr := fmt.Sprintf(":%d", serverPort)
	go func() {
		_ = router.Run(addr)
	}()
}

func buildSSLArgs() []string {
	var args []string
	if tracePID != 0 {
		args = append(args, "-p", fmt.Sprintf("%d", tracePID))
	}
	if traceSSLUID != 0 {
		args = append(args, "-u", fmt.Sprintf("%d", traceSSLUID))
	}
	if traceComm != "" && traceBinaryPath == "" {
		args = append(args, "-c", traceComm)
	}
	if traceSSLHandshake {
		args = append(args, "--handshake")
	}
	if traceBinaryPath != "" {
		args = append(args, "--binary-path", traceBinaryPath)
	}
	return args
}

func buildProcessArgs() []string {
	var args []string
	if traceComm != "" {
		args = append(args, "-c", traceComm)
	}
	if tracePID != 0 {
		args = append(args, "-p", fmt.Sprintf("%d", tracePID))
	}
	if traceDuration > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", traceDuration))
	}
	if traceMode > 0 {
		args = append(args, "-m", fmt.Sprintf("%d", traceMode))
	}
	return args
}
