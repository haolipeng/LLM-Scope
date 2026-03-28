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
	processDuration int
	processMode     int
	processComm     string
	processPID      int
)

var processCmd = &cobra.Command{
	Use:   "process",
	Short: "进程监控",
	Run:   runProcess,
}

func init() {
	rootCmd.AddCommand(processCmd)

	processCmd.Flags().IntVarP(&processDuration, "duration", "d", 0, "最小进程持续时间(毫秒)")
	processCmd.Flags().IntVarP(&processMode, "mode", "m", 0, "过滤模式: 0=all, 1=proc, 2=filter")
	processCmd.Flags().StringVarP(&processComm, "comm", "c", "", "进程名过滤(逗号分隔)")
	processCmd.Flags().IntVarP(&processPID, "pid", "p", 0, "PID 过滤")
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

	config := runner.ProcessConfig{
		MinDurationMs: int64(processDuration),
		PID:           processPID,
		FilterMode:    processMode,
	}
	if processComm != "" {
		config.Commands = splitComm(processComm)
	}

	procRunner := runner.NewProcessRunner(config)

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
