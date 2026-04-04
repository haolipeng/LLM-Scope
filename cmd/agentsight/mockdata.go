package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	pipelinesink "github.com/haolipeng/LLM-Scope/internal/pipeline/sink"
	"github.com/spf13/cobra"
)

var mockDuckDBPath string

var mockDataCmd = &cobra.Command{
	Use:   "mock-data",
	Short: "向 DuckDB 写入演示用安全告警数据（开发/联调）",
	Long: `在现有 DuckDB 中插入一条会话记录与若干条 events_security 行，便于 Web「安全告警」页联调。
不会清空已有数据；重复执行会追加新告警（会话行使用 INSERT OR IGNORE）。

示例：
  agentsight mock-data
  agentsight mock-data --duckdb-path /tmp/test.duckdb`,
	Run: runMockData,
}

func init() {
	mockDataCmd.Flags().StringVar(&mockDuckDBPath, "duckdb-path", "agentsight.duckdb", "DuckDB 文件路径（与 record/trace --duckdb-path 一致）")
	rootCmd.AddCommand(mockDataCmd)
}

const mockSessionID = "demo-mock-session"

func runMockData(cmd *cobra.Command, _ []string) {
	sink, err := pipelinesink.NewDuckDBSink(pipelinesink.DuckDBConfig{
		DBPath:    mockDuckDBPath,
		SessionID: "mock-data-tool",
	})
	if err != nil {
		cliErrf(cmd, "打开 DuckDB 失败: %v\n", err)
		os.Exit(1)
	}
	defer sink.Close()

	db := sink.DB()
	_, err = db.Exec(`INSERT OR IGNORE INTO sessions (session_id, start_time) VALUES (?, ?)`,
		mockSessionID, time.Now())
	if err != nil {
		cliErrf(cmd, "写入 sessions 失败: %v\n", err)
		os.Exit(1)
	}

	now := time.Now()
	samples := []struct {
		alertType   string
		risk        string
		description string
		sourceTable string
		srcEventID  uint64
	}{
		{"sensitive_file_access", "high", "模拟：进程读取敏感路径 /etc/shadow", "events_process", 1001},
		{"dangerous_command", "medium", "模拟：检测到潜在破坏性命令模式", "events_process", 1002},
		{"suspicious_network", "low", "模拟：非常见外连目标", "events_ssl", 1003},
	}

	for i, s := range samples {
		ts := now.Add(-time.Duration(len(samples)-i) * time.Minute)
		evidence := []map[string]interface{}{
			{
				"source_table": s.sourceTable,
				"event_type":   "MOCK",
				"pid":          4242 + uint32(i),
				"comm":         "mock-proc",
				"timestamp_ns": ts.UnixNano(),
				"detail":       "seeded by agentsight mock-data",
			},
		}
		evidenceJSON, _ := json.Marshal(evidence)
		payload := map[string]interface{}{
			"alert_type":        s.alertType,
			"risk_level":        s.risk,
			"description":       s.description,
			"source_table":      s.sourceTable,
			"source_event_id":     float64(s.srcEventID),
			"source_stream_seq":   "0",
			"evidence":            json.RawMessage(evidenceJSON),
		}
		dataJSON, _ := json.Marshal(payload)

		_, err = db.Exec(`
			INSERT INTO events_security (
				session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
				alert_type, risk_level, description, source_table, source_event_id,
				evidence_json, data_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::JSON, ?::JSON)`,
			mockSessionID,
			ts.UnixNano(),
			ts.UnixMilli(),
			ts,
			4242+uint32(i),
			"mock-proc",
			s.alertType,
			s.risk,
			s.description,
			s.sourceTable,
			s.srcEventID,
			string(evidenceJSON),
			string(dataJSON),
		)
		if err != nil {
			cliErrf(cmd, "写入 events_security 失败: %v\n", err)
			os.Exit(1)
		}
	}

	// 视图依赖表数据；若库已存在则无需刷新
	fmt.Fprintf(cmd.OutOrStdout(), "已写入会话 %q 与 %d 条演示告警 → %s\n", mockSessionID, len(samples), mockDuckDBPath)
}
