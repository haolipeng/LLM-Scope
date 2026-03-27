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
	stdioPID      int
	stdioUID      int
	stdioComm     string
	stdioAllFDs   bool
	stdioMaxBytes int
)

var stdioCmd = &cobra.Command{
	Use:   "stdio",
	Short: "监控进程 stdio",
	Long:  "捕获目标进程的标准输入/输出/错误流",
	Run:   runStdio,
}

func init() {
	rootCmd.AddCommand(stdioCmd)

	stdioCmd.Flags().IntVarP(&stdioPID, "pid", "p", 0, "目标进程 PID (必需)")
	stdioCmd.Flags().IntVarP(&stdioUID, "uid", "u", 0, "UID 过滤")
	stdioCmd.Flags().StringVarP(&stdioComm, "comm", "c", "", "进程名过滤")
	stdioCmd.Flags().BoolVar(&stdioAllFDs, "all-fds", false, "捕获所有 FD")
	stdioCmd.Flags().IntVar(&stdioMaxBytes, "max-bytes", 8192, "每事件最大字节数")

	_ = stdioCmd.MarkFlagRequired("pid")
}

func runStdio(cmd *cobra.Command, _ []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	stdioRunner := runner.NewStdioRunner(runner.StdioConfig{
		PID:      stdioPID,
		UID:      stdioUID,
		Comm:     stdioComm,
		AllFDs:   stdioAllFDs,
		MaxBytes: stdioMaxBytes,
	})

	var analyzers []analyzer.Analyzer
	if logFile != "" {
		analyzers = append(analyzers, analyzer.NewFileLogger(logFile, rotateLogs, maxLogSize))
	}
	if !quiet {
		analyzers = append(analyzers, analyzer.NewOutput())
	}

	events, err := stdioRunner.Run(ctx)
	if err != nil {
		cmd.PrintErrf("启动失败: %v\n", err)
		os.Exit(1)
	}

	out := analyzer.Chain(analyzers...).Process(ctx, events)
	for range out {
	}
}
