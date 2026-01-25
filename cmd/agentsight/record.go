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

func runRecord(cmd *cobra.Command, _ []string) {
	traceSSL = true
	traceProcess = true
	traceSystem = false
	traceComm = recordComm
	tracePID = 0
	traceSSLUID = 0
	traceSSLFilter = []string{"data=0\r\n\r\n|data.type=binary"}
	traceSSLHandshake = false
	traceSSLHTTP = true
	traceSSLRaw = false
	traceHTTPFilter = []string{"request.path_prefix=/v1/rgstr | response.status_code=202 | request.method=HEAD | response.body="}
	traceDisableAuth = false
	traceDuration = 0
	traceMode = 0
	traceSystemInterval = 2
	traceBinaryPath = recordBinaryPath

	logFile = recordLogFile
	rotateLogs = recordRotate
	maxLogSize = recordMaxSize
	server = true
	serverPort = recordServerPort

	runTrace(cmd, nil)
}
