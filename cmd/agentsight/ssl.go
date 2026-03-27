package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/haolipeng/LLM-Scope/internal/analyzer"
	"github.com/haolipeng/LLM-Scope/internal/runner"
	"github.com/spf13/cobra"
)

var (
	sseMerge           bool
	httpParser         bool
	httpRawData        bool
	httpFilters        []string
	sslFilters         []string
	disableAuthRemoval bool
	binaryPath         string
)

var sslCmd = &cobra.Command{
	Use:   "ssl [-- EBPF_ARGS]",
	Short: "监控 SSL/TLS 流量",
	Long:  "捕获应用程序的 SSL/TLS 加密流量，获取解密后的明文数据",
	Run:   runSSL,
}

func init() {
	rootCmd.AddCommand(sslCmd)

	sslCmd.Flags().BoolVar(&sseMerge, "sse-merge", false, "启用 SSE 事件合并")
	sslCmd.Flags().BoolVar(&httpParser, "http-parser", false, "启用 HTTP 解析")
	sslCmd.Flags().BoolVar(&httpRawData, "http-raw-data", false, "包含原始数据")
	sslCmd.Flags().StringArrayVar(&httpFilters, "http-filter", nil, "HTTP 过滤表达式")
	sslCmd.Flags().StringArrayVar(&sslFilters, "ssl-filter", nil, "SSL 过滤表达式")
	sslCmd.Flags().BoolVar(&disableAuthRemoval, "disable-auth-removal", false, "禁用敏感头移除")
	sslCmd.Flags().StringVar(&binaryPath, "binary-path", "", "SSL 库二进制路径")
}

func runSSL(cmd *cobra.Command, args []string) {
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

	sslRunner := runner.NewSSLRunner(runner.SSLConfig{
		Args:       args,
		BinaryPath: binaryPath,
	})

	var analyzers []analyzer.Analyzer
	if len(sslFilters) > 0 {
		analyzers = append(analyzers, analyzer.NewSSLFilter(sslFilters))
	}
	if httpParser || sseMerge {
		analyzers = append(analyzers, analyzer.NewSSEMerger())
	}
	if httpParser {
		analyzers = append(analyzers, analyzer.NewHTTPParser(httpRawData))
		if len(httpFilters) > 0 {
			analyzers = append(analyzers, analyzer.NewHTTPFilter(httpFilters))
		}
		if !disableAuthRemoval {
			analyzers = append(analyzers, analyzer.NewAuthRemover())
		}
	}
	analyzers = append(analyzers, analyzer.NewToolCallAggregator())
	if logFile != "" {
		analyzers = append(analyzers, analyzer.NewFileLogger(logFile, rotateLogs, maxLogSize))
	}
	if !quiet {
		analyzers = append(analyzers, analyzer.NewOutput())
	}

	events, err := sslRunner.Run(ctx)
	if err != nil {
		cmd.PrintErrf("启动失败: %v\n", err)
		os.Exit(1)
	}

	out := analyzer.Chain(analyzers...).Process(ctx, events)

	for range out {
	}
}
