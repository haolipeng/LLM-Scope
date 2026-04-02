package main

import (
	"os"

	"github.com/haolipeng/LLM-Scope/internal/pipeline"
	pipelinetransforms "github.com/haolipeng/LLM-Scope/internal/pipeline/transforms"
	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	processcollector "github.com/haolipeng/LLM-Scope/internal/collectors/process"
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

// runProcess 启动进程监控 runner 并连接 analyzer 管道
func runProcess(cmd *cobra.Command, args []string) {
	config := processcollector.Config{
		MinDurationMs: int64(processDuration),
		PID:           processPID,
		FilterMode:    processMode,
	}
	if processComm != "" {
		config.Commands = splitComm(processComm)
	}

	err := pipeline.Execute(pipeline.ExecuteConfig{
		Runner:     processcollector.New(config),
		Analyzers:  []pipelinetypes.Analyzer{pipelinetransforms.NewToolCallAggregator()},
		LogFile:    logFile,
		RotateLogs: rotateLogs,
		MaxLogSize: maxLogSize,
		Quiet:      quiet,
	})
	if err != nil {
		cmd.PrintErrf("启动失败: %v\n", err)
		os.Exit(1)
	}
}
