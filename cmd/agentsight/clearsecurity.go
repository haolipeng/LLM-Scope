package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/marcboeker/go-duckdb"
	"github.com/spf13/cobra"
)

var clearSecurityDuckDBPath string

var clearSecurityCmd = &cobra.Command{
	Use:   "clear-security-alerts",
	Short: "清空 DuckDB 中的安全告警表 events_security",
	Long: `删除 events_security 中全部行（视图 v_security_alerts 随之为空）。
用于联调前重置告警数据；不影响其它事件表。

示例：
  ./agentsight clear-security-alerts
  ./agentsight clear-security-alerts --duckdb-path ./agentsight.duckdb`,
	Run: runClearSecurity,
}

func init() {
	clearSecurityCmd.Flags().StringVar(&clearSecurityDuckDBPath, "duckdb-path", "agentsight.duckdb", "DuckDB 文件路径（与 record --duckdb-path 一致）")
	rootCmd.AddCommand(clearSecurityCmd)
}

func runClearSecurity(cmd *cobra.Command, _ []string) {
	db, err := sql.Open("duckdb", clearSecurityDuckDBPath)
	if err != nil {
		cliErrf(cmd, "打开 DuckDB 失败: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	res, err := db.Exec("DELETE FROM events_security")
	if err != nil {
		cliErrf(cmd, "清空 events_security 失败: %v\n", err)
		os.Exit(1)
	}
	n, _ := res.RowsAffected()
	fmt.Fprintf(cmd.OutOrStdout(), "已清空 events_security（删除约 %d 行）→ %s\n", n, clearSecurityDuckDBPath)
}
