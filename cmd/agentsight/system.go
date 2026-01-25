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

var (
	systemInterval     int
	systemPID          int
	systemComm         string
	systemNoChildren   bool
	systemCPUThreshold float64
	systemMemThreshold int
)

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "系统资源监控",
	Run:   runSystem,
}

func init() {
	rootCmd.AddCommand(systemCmd)

	systemCmd.Flags().IntVarP(&systemInterval, "interval", "i", 2, "监控间隔(秒)")
	systemCmd.Flags().IntVarP(&systemPID, "pid", "p", 0, "监控特定 PID")
	systemCmd.Flags().StringVarP(&systemComm, "comm", "c", "", "按进程名监控")
	systemCmd.Flags().BoolVar(&systemNoChildren, "no-children", false, "排除子进程")
	systemCmd.Flags().Float64Var(&systemCPUThreshold, "cpu-threshold", 0, "CPU 告警阈值%")
	systemCmd.Flags().IntVar(&systemMemThreshold, "memory-threshold", 0, "内存告警阈值MB")
}

func runSystem(cmd *cobra.Command, _ []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	sysRunner := runner.NewSystemRunner(runner.SystemConfig{
		IntervalSeconds: systemInterval,
		PID:             systemPID,
		Comm:            systemComm,
		IncludeChildren: !systemNoChildren,
		CPUThreshold:    systemCPUThreshold,
		MemoryThreshold: systemMemThreshold,
	})

	var analyzers []analyzer.Analyzer
	if logFile != "" {
		analyzers = append(analyzers, analyzer.NewFileLogger(logFile, rotateLogs, maxLogSize))
	}
	if !quiet {
		analyzers = append(analyzers, analyzer.NewOutput())
	}

	events, err := sysRunner.Run(ctx)
	if err != nil {
		cmd.PrintErrf("启动失败: %v\n", err)
		os.Exit(1)
	}

	out := analyzer.Chain(analyzers...).Process(ctx, events)
	for range out {
	}
}
