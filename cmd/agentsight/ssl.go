package main

import (
	"os"

	sslcollector "github.com/haolipeng/LLM-Scope/internal/collectors/ssl"
	"github.com/haolipeng/LLM-Scope/internal/pipeline"
	pipelinetransforms "github.com/haolipeng/LLM-Scope/internal/pipeline/transforms"
	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
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
	sslHTTPPCap string
)

var sslCmd = &cobra.Command{
	Use:   "ssl",
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
	sslCmd.Flags().StringVar(&sslHTTPPCap, "http-pcap", "", "将解析后的 HTTP 写入合成 TCP 的 pcap 文件路径（需 --http-parser，空则关闭）")
}

// buildSSLCmdHTTPAnalyzers 构建 ssl 命令的 HTTP 解析器链
func buildSSLCmdHTTPAnalyzers(cmd *cobra.Command) []pipelinetypes.Analyzer {
	includeRaw := httpRawData || sslHTTPPCap != ""
	analyzers := []pipelinetypes.Analyzer{pipelinetransforms.NewHTTPParser(includeRaw)}
	if sslHTTPPCap != "" {
		pcapW, err := pipelinetransforms.NewHTTPPCAPWriter(sslHTTPPCap)
		if err != nil {
			cliErrf(cmd, "HTTP pcap: %v\n", err)
			os.Exit(1)
		}
		if pcapW != nil {
			analyzers = append(analyzers, pcapW)
		}
	}
	if len(httpFilters) > 0 {
		analyzers = append(analyzers, pipelinetransforms.NewHTTPFilter(httpFilters))
	}
	if !disableAuthRemoval {
		analyzers = append(analyzers, pipelinetransforms.NewAuthRemover())
	}
	return analyzers
}

// runSSL 启动 SSL/TLS 流量监控并连接分析管道
func runSSL(cmd *cobra.Command, args []string) {
	if sslHTTPPCap != "" && !httpParser {
		cliErrln(cmd, "--http-pcap 需要同时指定 --http-parser")
		os.Exit(1)
	}

	var analyzers []pipelinetypes.Analyzer
	if len(sslFilters) > 0 {
		analyzers = append(analyzers, pipelinetransforms.NewSSLFilter(sslFilters))
	}
	if httpParser || sseMerge {
		analyzers = append(analyzers, pipelinetransforms.NewSSEMerger())
	}
	if httpParser {
		analyzers = append(analyzers, buildSSLCmdHTTPAnalyzers(cmd)...)
	}
	analyzers = append(analyzers, pipelinetransforms.NewToolCallAggregator())

	err := pipeline.Execute(pipeline.ExecuteConfig{
		Runner: sslcollector.New(sslcollector.Config{
			OpenSSL:    true,
			BinaryPath: binaryPath,
		}),
		Analyzers:  analyzers,
		LogFile:    logFile,
		RotateLogs: rotateLogs,
		MaxLogSize: maxLogSize,
		Quiet:      quiet,
		OnSignal: func() {
			for _, a := range analyzers {
				if r, ok := a.(pipelinetypes.MetricsReporter); ok {
					r.ReportMetrics()
				}
			}
		},
	})
	if err != nil {
		cliErrf(cmd, "启动失败: %v\n", err)
		os.Exit(1)
	}
}
