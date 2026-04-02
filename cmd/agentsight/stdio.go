package main

import (
	"os"

	"github.com/haolipeng/LLM-Scope/internal/pipeline"
	stdiocollector "github.com/haolipeng/LLM-Scope/internal/collectors/stdio"
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

// runStdio 启动标准 I/O 捕获并连接 analyzer 管道
func runStdio(cmd *cobra.Command, _ []string) {
	err := pipeline.Execute(pipeline.ExecuteConfig{
		Runner: stdiocollector.New(stdiocollector.Config{
			PID:      stdioPID,
			UID:      stdioUID,
			Comm:     stdioComm,
			AllFDs:   stdioAllFDs,
			MaxBytes: stdioMaxBytes,
		}),
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
