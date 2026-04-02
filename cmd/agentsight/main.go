package main

import (
	"os"

	"github.com/haolipeng/LLM-Scope/frontend"
	agentsightserver "github.com/haolipeng/LLM-Scope/internal/httpserver"
	"github.com/haolipeng/LLM-Scope/internal/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	cfgFile    string
	server     bool
	serverPort int
	logFile    string
	quiet      bool
	rotateLogs bool
	maxLogSize int
)

var rootCmd = &cobra.Command{
	Use:   "agentsight",
	Short: "AI Agent 可观测性框架",
	Long:  "AgentSight 通过 eBPF 技术监控 AI Agent 的 SSL/TLS 流量和进程行为",
}

func init() {
	// Register embedded frontend assets
	agentsightserver.SetEmbeddedFrontend(frontend.DistFS)

	cobra.OnInitialize(initConfig)

	// 初始化全局命令行标志
	rootCmd.PersistentFlags().BoolVar(&server, "server", false, "启动 Web 服务器")
	rootCmd.PersistentFlags().IntVar(&serverPort, "server-port", 7395, "Web 服务器端口")
	rootCmd.PersistentFlags().StringVarP(&logFile, "log-file", "o", "", "日志文件路径")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "禁用控制台输出")
	rootCmd.PersistentFlags().BoolVar(&rotateLogs, "rotate-logs", false, "启用日志轮转")
	rootCmd.PersistentFlags().IntVar(&maxLogSize, "max-log-size", 10, "最大日志大小(MB)")

	viper.BindPFlag("server", rootCmd.PersistentFlags().Lookup("server"))
	viper.BindPFlag("server-port", rootCmd.PersistentFlags().Lookup("server-port"))
}

// initConfig 加载配置文件和环境变量
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}
	viper.AutomaticEnv()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logging.NamedZap("cmd").Error("命令执行失败", zap.Error(err))
		os.Exit(1)
	}
}
