package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/eunomia-bpf/agentsight/internal/analyzer"
	"github.com/eunomia-bpf/agentsight/internal/runner"
	"github.com/spf13/cobra"
)

var processCmd = &cobra.Command{
	Use:   "process [-- EBPF_ARGS]",
	Short: "进程监控",
	Run:   runProcess,
}

func init() {
	rootCmd.AddCommand(processCmd)
}

func runProcess(cmd *cobra.Command, args []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	procRunner := runner.NewProcessRunner(runner.ProcessConfig{Args: args})

	var analyzers []analyzer.Analyzer
	analyzers = append(analyzers, analyzer.NewToolCallAggregator())
	if logFile != "" {
		analyzers = append(analyzers, analyzer.NewFileLogger(logFile, rotateLogs, maxLogSize))
	}
	if !quiet {
		analyzers = append(analyzers, analyzer.NewOutput())
	}

	events, err := procRunner.Run(ctx)
	if err != nil {
		cmd.PrintErrf("启动失败: %v\n", err)
		os.Exit(1)
	}

	out := analyzer.Chain(analyzers...).Process(ctx, events)
	for range out {
	}
}
