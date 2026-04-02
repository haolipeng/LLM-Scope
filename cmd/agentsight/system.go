package main

import (
	"os"

	systemcollector "github.com/haolipeng/LLM-Scope/internal/collectors/system"
	"github.com/haolipeng/LLM-Scope/internal/pipeline"
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

	systemCmd.Flags().IntVarP(&systemInterval, "interval", "i", 10, "监控间隔(秒)")
	systemCmd.Flags().IntVarP(&systemPID, "pid", "p", 0, "监控特定 PID")
	systemCmd.Flags().StringVarP(&systemComm, "comm", "c", "", "按进程名监控")
	systemCmd.Flags().BoolVar(&systemNoChildren, "no-children", false, "排除子进程")
	systemCmd.Flags().Float64Var(&systemCPUThreshold, "cpu-threshold", 0, "CPU 告警阈值%")
	systemCmd.Flags().IntVar(&systemMemThreshold, "memory-threshold", 0, "内存告警阈值MB")
}

// runSystem 启动系统资源监控并连接 analyzer 管道
func runSystem(cmd *cobra.Command, _ []string) {
	err := pipeline.Execute(pipeline.ExecuteConfig{
		Runner: systemcollector.New(systemcollector.Config{
			IntervalSeconds: systemInterval,
			PID:             systemPID,
			Comm:            systemComm,
			IncludeChildren: !systemNoChildren,
			CPUThreshold:    systemCPUThreshold,
			MemoryThreshold: systemMemThreshold,
		}),
		LogFile:    logFile,
		RotateLogs: rotateLogs,
		MaxLogSize: maxLogSize,
		Quiet:      quiet,
	})
	if err != nil {
		cliErrf(cmd, "启动失败: %v\n", err)
		os.Exit(1)
	}
}
