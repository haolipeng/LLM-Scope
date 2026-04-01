package main

import (
	"github.com/spf13/cobra"
)

var (
	recordComm       string
	recordBinaryPath string
	recordLogFile    string
	recordRotate     bool
	recordMaxSize    int
	recordServerPort int
)

var recordCmd = &cobra.Command{
	Use:   "record",
	Short: "AI Agent 录制",
	Run:   runRecord,
}

func init() {
	rootCmd.AddCommand(recordCmd)

	recordCmd.Flags().StringVarP(&recordComm, "comm", "c", "", "要监控的进程名")
	recordCmd.Flags().StringVar(&recordBinaryPath, "binary-path", "", "二进制路径")
	recordCmd.Flags().StringVarP(&recordLogFile, "log-file", "o", "record.log", "日志文件")
	recordCmd.Flags().BoolVar(&recordRotate, "rotate-logs", true, "日志轮转")
	recordCmd.Flags().IntVar(&recordMaxSize, "max-log-size", 10, "最大日志大小(MB)")
	recordCmd.Flags().IntVar(&recordServerPort, "server-port", 7395, "Web 端口")

	_ = recordCmd.MarkFlagRequired("comm")
}

// runRecord 用预设配置启动 AI Agent 录制会话
func runRecord(cmd *cobra.Command, _ []string) {
	cfg := TraceConfig{
		Comm: recordComm,
		PID:  0,
		SSL: TraceSSLConfig{
			Enabled:     true,
			UID:         0,
			Filter:      []string{"data=0\r\n\r\n|data.type=binary"},
			Handshake:   false,
			HTTP:        true,
			Raw:         false,
			HTTPFilter:  []string{"request.path_prefix=/v1/rgstr | response.status_code=202 | request.method=HEAD | response.body="},
			DisableAuth: false,
			BinaryPath:  recordBinaryPath,
		},
		Process: TraceProcessConfig{
			Enabled:  true,
			Duration: 0,
			Mode:     0,
		},
		System: TraceSystemConfig{
			Enabled:  true,
			Interval: 10,
		},
		Output: OutputConfig{
			Quiet:      true,
			LogFile:    recordLogFile,
			RotateLogs: recordRotate,
			MaxLogSize: recordMaxSize,
			Server:     true,
			ServerPort: recordServerPort,
		},
	}
	executeTrace(cmd, cfg)
}
