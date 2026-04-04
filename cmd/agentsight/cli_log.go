package main

import (
	"fmt"
	"strings"

	"github.com/haolipeng/LLM-Scope/internal/logging"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// cliErrf 先写入应用日志（便于落盘检索），再调用 Cobra 输出到 stderr，终端行为与 PrintErrf 一致。
func cliErrf(cmd *cobra.Command, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logging.NamedZap("cmd").Error("cli", zap.String("message", strings.TrimSuffix(msg, "\n")))
	cmd.PrintErrf("%s", msg)
}

// cliErrln 同上，单行信息。
func cliErrln(cmd *cobra.Command, msg string) {
	logging.NamedZap("cmd").Error("cli", zap.String("message", msg))
	cmd.PrintErrln(msg)
}
