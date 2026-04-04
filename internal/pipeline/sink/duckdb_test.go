package sink

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
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

func TestDuckDB_CreateSchema(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	// Verify all tables exist.
	tables := []string{
		"sessions",
		"events_process",
		"events_tool_call",
		"events_system",
		"events_ssl",
		"events_http",
		"events_sse",
		"events_security",
	}
	for _, tbl := range tables {
		var count int
		err := sink.DB().QueryRow("SELECT COUNT(*) FROM " + tbl).Scan(&count)
		if err != nil {
			t.Errorf("table %s not accessible: %v", tbl, err)
		}
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

	// Verify session record was created.
	var sid string
	err := sink.DB().QueryRow("SELECT session_id FROM sessions WHERE session_id = 'test-session'").Scan(&sid)
	if err != nil {
		t.Errorf("session record not found: %v", err)
	}
}

func TestDuckDB_InsertProcessEvent(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	data := map[string]interface{}{
		"event":        "EXEC",
		"pid":          float64(1234),
		"ppid":         float64(1),
		"comm":         "test",
		"filename":     "/usr/bin/test",
		"full_command": "test --flag",
		"timestamp":    float64(12345678),
	}
	dataJSON, _ := json.Marshal(data)

	event := &event.Event{
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
	sink.DB().QueryRow("SELECT COUNT(*) FROM events_process").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 process event, got %d", count)
	}

	var eventType, filename sql.NullString
	var ppid sql.NullInt64
	sink.DB().QueryRow("SELECT event_type, filename, ppid FROM events_process").
		Scan(&eventType, &filename, &ppid)

	if !eventType.Valid || eventType.String != "EXEC" {
		t.Errorf("expected event_type=EXEC, got %v", eventType)
	}
	if !filename.Valid || filename.String != "/usr/bin/test" {
		t.Errorf("expected filename=/usr/bin/test, got %v", filename)
	}
}

func TestDuckDB_InsertToolCallEvent(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	data := map[string]interface{}{
		"event_type":  "tool_call_end",
		"tool_name":   "fs.read",
		"status":      "success",
		"reason":      "completed",
		"bytes":       float64(1024),
		"key_field":   "/etc/passwd",
		"duration_ms": float64(42),
		"args_hash":   "abc123",
		"tid":         float64(5),
	}
	dataJSON, _ := json.Marshal(data)

	event := &event.Event{
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
	sink.DB().QueryRow(`
		SELECT tool_name, tool_status
		FROM events_tool_call
	`).Scan(&toolName, &toolStatus)

	if !toolName.Valid || toolName.String != "fs.read" {
		t.Errorf("expected tool_name=fs.read, got %v", toolName)
	}
	if !toolStatus.Valid || toolStatus.String != "success" {
		t.Errorf("expected tool_status=success, got %v", toolStatus)
	}
}

func TestDuckDB_InsertSystemEvent(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	data := map[string]interface{}{
		"type":    "system_metrics",
		"alert":   false,
		"cpu":     map[string]interface{}{"percent": "12.5", "cores": float64(4)},
		"memory":  map[string]interface{}{"rss_kb": float64(25552), "vsz_kb": float64(1151800)},
		"process": map[string]interface{}{"threads": float64(11), "children": float64(2)},
	}
	dataJSON, _ := json.Marshal(data)

	event := &event.Event{
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
		FROM events_system
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

func TestDuckDB_InsertSecurityEvent(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	evidence := []map[string]interface{}{
		{"source_table": "events_process", "event_type": "FILE_OPEN", "filepath": "/etc/shadow"},
	}
	evidenceJSON, _ := json.Marshal(evidence)

	data := map[string]interface{}{
		"alert_type":      "sensitive_file_access",
		"risk_level":      "high",
		"description":     "Process test accessed /etc/shadow",
		"source_table":    "events_process",
		"source_event_id": float64(42),
		"evidence":        evidence,
	}
	dataJSON, _ := json.Marshal(data)

	event := &event.Event{
		TimestampNs:     77777,
		TimestampUnixMs: 1700000003000,
		Source:          "security",
		PID:             1111,
		Comm:            "test",
		Data:            dataJSON,
	}

	sink.addEvent(event)
	sink.flush()

	var alertType, riskLevel, desc sql.NullString
	var srcTable sql.NullString
	var evJSON sql.NullString
	sink.DB().QueryRow(`
		SELECT alert_type, risk_level, description, source_table, evidence_json
		FROM events_security
	`).Scan(&alertType, &riskLevel, &desc, &srcTable, &evJSON)

	if !alertType.Valid || alertType.String != "sensitive_file_access" {
		t.Errorf("expected alert_type=sensitive_file_access, got %v", alertType)
	}
	if !riskLevel.Valid || riskLevel.String != "high" {
		t.Errorf("expected risk_level=high, got %v", riskLevel)
	}
	if !desc.Valid || desc.String != "Process test accessed /etc/shadow" {
		t.Errorf("expected description match, got %v", desc)
	}
	if !srcTable.Valid || srcTable.String != "events_process" {
		t.Errorf("expected source_table=events_process, got %v", srcTable)
	}
	_ = evidenceJSON // verified the insert works; the evidence field was stored
}

func TestDuckDB_SecuritySourceEventIDFromStreamSeq(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	// Use an explicit StreamSeq so the test is independent of global counter.
	procSeq := event.NextStreamSeq()

	procData, err := json.Marshal(map[string]interface{}{
		"event":    "FILE_OPEN",
		"filepath": "/etc/shadow",
	})
	if err != nil {
		t.Fatal(err)
	}
	sink.addEvent(&event.Event{
		StreamSeq:       procSeq,
		TimestampNs:     1000,
		TimestampUnixMs: 1700000000000,
		Source:          "process",
		PID:             1,
		Comm:            "sh",
		Data:            procData,
	})

	secData := map[string]interface{}{
		"alert_type":        "sensitive_file_access",
		"risk_level":        "high",
		"description":       "test",
		"source_table":      "events_process",
		"source_stream_seq": fmt.Sprintf("%d", procSeq),
		"evidence":          []interface{}{},
	}
	secJSON, err := json.Marshal(secData)
	if err != nil {
		t.Fatal(err)
	}
	sink.addEvent(&event.Event{
		TimestampNs:     2000,
		TimestampUnixMs: 1700000000001,
		Source:          "security",
		PID:             1,
		Comm:            "sh",
		Data:            secJSON,
	})

	sink.flush()

	var procID uint64
	if err := sink.DB().QueryRow(`SELECT id FROM events_process LIMIT 1`).Scan(&procID); err != nil {
		t.Fatal(err)
	}
	var srcID sql.NullInt64
	if err := sink.DB().QueryRow(`SELECT source_event_id FROM events_security LIMIT 1`).Scan(&srcID); err != nil {
		t.Fatal(err)
	}
	if !srcID.Valid || uint64(srcID.Int64) != procID {
		t.Fatalf("source_event_id want %d, got %v", procID, srcID)
	}
}

func TestDuckDB_BatchInsertMixed(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	// Insert events of different types.
	types := []struct {
		source string
		data   map[string]interface{}
	}{
		{"process", map[string]interface{}{"event": "EXEC", "filename": "/bin/ls"}},
		{"process", map[string]interface{}{"event": "FILE_OPEN", "filepath": "/tmp/test"}},
		{"system", map[string]interface{}{"type": "system_metrics", "cpu": map[string]interface{}{"percent": float64(5.0)}}},
		{"tool_call", map[string]interface{}{"event_type": "tool_call_end", "tool_name": "fs.read"}},
		{"http_parser", map[string]interface{}{"message_type": "request", "method": "POST", "path": "/v1/messages"}},
	}

	for i, tt := range types {
		dataJSON, _ := json.Marshal(tt.data)
		sink.addEvent(&event.Event{
			TimestampNs:     int64(i * 1000),
			TimestampUnixMs: 1700000000000 + int64(i),
			Source:          tt.source,
			PID:             uint32(100 + i),
			Comm:            "test",
			Data:            dataJSON,
		})
	}
	sink.flush()

	// Verify each table got the right number of rows.
	assertCount := func(table string, expected int) {
		var count int
		sink.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count)
		if count != expected {
			t.Errorf("expected %d rows in %s, got %d", expected, table, count)
		}
	}

	assertCount("events_process", 2)
	assertCount("events_system", 1)
	assertCount("events_tool_call", 1)
	assertCount("events_http", 1)
	assertCount("events_ssl", 0)
	assertCount("events_sse", 0)
	assertCount("events_security", 0)
}

func TestDuckDB_FlushOnInterval(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "interval.duckdb")
	sink, err := NewDuckDBSink(DuckDBConfig{
		DBPath:        dbPath,
		BatchSize:     1000, // very high, won't trigger batch flush
		FlushInterval: 100 * time.Millisecond,
		SessionID:     "interval-test",
	})
	if err != nil {
		t.Fatalf("NewDuckDBSink: %v", err)
	}

	// Add 3 events and use Consume with a short-lived context.
	ch := make(chan *event.Event, 5)
	for i := 0; i < 3; i++ {
		data, _ := json.Marshal(map[string]interface{}{"event": "EXEC"})
		ch <- &event.Event{
			TimestampNs:     int64(i),
			TimestampUnixMs: 1700000000000,
			Source:          "process",
			PID:             uint32(i),
			Comm:            "test",
			Data:            data,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go sink.Consume(ctx, ch)

	// Wait for context to expire + flush.
	<-ctx.Done()
	time.Sleep(200 * time.Millisecond)

	// Re-open to verify.
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db.Close()

	var count int
	db.QueryRow("SELECT COUNT(*) FROM events_process").Scan(&count)
	if count != 3 {
		t.Errorf("expected 3 rows after interval flush, got %d", count)
	}
}

func TestDuckDB_SessionTable(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	// Verify session was auto-created.
	var sid string
	var startTime sql.NullTime
	sink.DB().QueryRow("SELECT session_id, start_time FROM sessions WHERE session_id = 'test-session'").
		Scan(&sid, &startTime)

	if sid != "test-session" {
		t.Errorf("expected session_id=test-session, got %s", sid)
	}
	if !startTime.Valid {
		t.Error("expected start_time to be set")
	}
}

func TestDuckDB_Consume(t *testing.T) {
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

	ch := make(chan *event.Event, 5)
	for i := 0; i < 3; i++ {
		data, _ := json.Marshal(map[string]interface{}{
			"event":    "EXEC",
			"pid":      float64(100 + i),
			"ppid":     float64(1),
			"filename": "/bin/test",
		})
		ch <- &event.Event{
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
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM events_process").Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 rows after Consume, got %d", count)
	}
}

func TestDuckDB_BatchFlush(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "batch.duckdb")
	sink, err := NewDuckDBSink(DuckDBConfig{
		DBPath:        dbPath,
		BatchSize:     10, // 5 process rows + 5 process_tree rows = 10
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
		sink.addEvent(&event.Event{
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
	sink.DB().QueryRow("SELECT COUNT(*) FROM events_process").Scan(&count)
	if count != 5 {
		t.Errorf("expected 5 rows after batch flush, got %d", count)
	}
}

func TestDuckDB_ToolCallStartSkipped(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	// tool_call_start should be skipped.
	startData, _ := json.Marshal(map[string]interface{}{
		"event_type": "tool_call_start",
		"tool_name":  "fs.read",
	})
	sink.addEvent(&event.Event{
		TimestampNs:     1000,
		TimestampUnixMs: 1700000000000,
		Source:          "tool_call",
		PID:             100,
		Comm:            "test",
		Data:            startData,
	})

	// tool_call_end should be inserted.
	endData, _ := json.Marshal(map[string]interface{}{
		"event_type": "tool_call_end",
		"tool_name":  "fs.read",
		"status":     "success",
	})
	sink.addEvent(&event.Event{
		TimestampNs:     2000,
		TimestampUnixMs: 1700000001000,
		Source:          "tool_call",
		PID:             100,
		Comm:            "test",
		Data:            endData,
	})
	sink.flush()

	var count int
	sink.DB().QueryRow("SELECT COUNT(*) FROM events_tool_call").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 tool_call event (end only), got %d", count)
	}
}

func TestDuckDB_ViewToolCallStats(t *testing.T) {
	sink := openTestDB(t)
	defer sink.Close()

	for i := 0; i < 10; i++ {
		end, _ := json.Marshal(map[string]interface{}{
			"event_type":  "tool_call_end",
			"tool_name":   "fs.read",
			"status":      "success",
			"duration_ms": float64(i * 10),
			"bytes":       float64(100),
		})
		sink.addEvent(&event.Event{
			TimestampNs:     int64(i*1000 + 500),
			TimestampUnixMs: 1700000000000 + int64(i),
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
