package sink

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/haolipeng/LLM-Scope/internal/event"
	"github.com/haolipeng/LLM-Scope/internal/logging"

	"go.uber.org/zap"
)

// DuckDBConfig controls DuckDBSink behaviour.
type DuckDBConfig struct {
	DBPath        string        // database file path, default "agentsight.duckdb"
	BatchSize     int           // flush threshold, default 1000
	FlushInterval time.Duration // periodic flush, default 5s
	SessionID     string        // session identifier, auto-generated when empty
}

func (c *DuckDBConfig) defaults() {
	if c.DBPath == "" {
		c.DBPath = "agentsight.duckdb"
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 1000
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 5 * time.Second
	}
	if c.SessionID == "" {
		c.SessionID = time.Now().Format("20060102-150405")
	}
}

// bufferedEvents holds events grouped by source for batch insertion.
type bufferedEvents struct {
	process  []processRow
	toolCall []toolCallRow
	system   []systemRow
	ssl      []sslRow
	http     []httpRow
	sse      []sseRow
	security []securityRow
}

func (b *bufferedEvents) total() int {
	return len(b.process) + len(b.toolCall) + len(b.system) +
		len(b.ssl) + len(b.http) + len(b.sse) + len(b.security)
}

func (b *bufferedEvents) reset() {
	b.process = b.process[:0]
	b.toolCall = b.toolCall[:0]
	b.system = b.system[:0]
	b.ssl = b.ssl[:0]
	b.http = b.http[:0]
	b.sse = b.sse[:0]
	b.security = b.security[:0]
}

// DuckDBSink implements pipelinetypes.Sink and writes events into a DuckDB
// database using batched inserts into per-source tables.
type DuckDBSink struct {
	db  *sql.DB
	cfg DuckDBConfig
	mu  sync.Mutex
	buf bufferedEvents
}

// NewDuckDBSink opens (or creates) the database, runs schema DDL, and returns
// a ready-to-use sink. The caller must eventually call Close().
func NewDuckDBSink(cfg DuckDBConfig) (*DuckDBSink, error) {
	cfg.defaults()

	db, err := sql.Open("duckdb", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("duckdb open: %w", err)
	}

	// Apply schema.
	for _, ddl := range allSchemaSQL {
		if _, err := db.Exec(ddl); err != nil {
			db.Close()
			return nil, fmt.Errorf("duckdb schema: %w", err)
		}
	}

	// Ensure session record exists.
	_, _ = db.Exec(
		"INSERT INTO sessions (session_id, start_time) VALUES (?, ?) ON CONFLICT DO NOTHING",
		cfg.SessionID, time.Now(),
	)

	s := &DuckDBSink{
		db:  db,
		cfg: cfg,
	}
	return s, nil
}

func (s *DuckDBSink) Name() string { return "duckdb" }

// DB exposes the underlying connection for analytics queries.
func (s *DuckDBSink) DB() *sql.DB { return s.db }

// Consume reads events from the channel and writes them to DuckDB in batches.
func (s *DuckDBSink) Consume(ctx context.Context, in <-chan *event.Event) {
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()
	defer s.flushAndClose()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-in:
			if !ok {
				return
			}
			s.addEvent(event)
		case <-ticker.C:
			s.flush()
		}
	}
}

var toolCallStartPrefix = []byte(`"event_type":"tool_call_start"`)

func (s *DuckDBSink) addEvent(event *event.Event) {
	// Skip tool_call_start events (only persist tool_call_end).
	if event.Source == "tool_call" && bytes.Contains(event.Data, toolCallStartPrefix) {
		return
	}

	s.mu.Lock()
	switch event.Source {
	case "process":
		s.buf.process = append(s.buf.process, extractProcessRow(event, s.cfg.SessionID))
	case "tool_call":
		s.buf.toolCall = append(s.buf.toolCall, extractToolCallRow(event, s.cfg.SessionID))
	case "system":
		s.buf.system = append(s.buf.system, extractSystemRow(event, s.cfg.SessionID))
	case "ssl":
		s.buf.ssl = append(s.buf.ssl, extractSSLRow(event, s.cfg.SessionID))
	case "http_parser":
		s.buf.http = append(s.buf.http, extractHTTPRow(event, s.cfg.SessionID))
	case "sse_processor":
		s.buf.sse = append(s.buf.sse, extractSSERow(event, s.cfg.SessionID))
	case "security":
		s.buf.security = append(s.buf.security, extractSecurityRow(event, s.cfg.SessionID))
	}
	needFlush := s.buf.total() >= s.cfg.BatchSize
	s.mu.Unlock()

	if needFlush {
		s.flush()
	}
}

func (s *DuckDBSink) flush() {
	s.mu.Lock()
	if s.buf.total() == 0 {
		s.mu.Unlock()
		return
	}
	// Swap out current buffer.
	batch := s.buf
	s.buf = bufferedEvents{}
	s.mu.Unlock()

	total := batch.total()
	if err := s.insertBatch(&batch); err != nil {
		logging.NamedZap("duckdb").Error("flush error", zap.Int("rows", total), zap.Error(err))
	}
}

func (s *DuckDBSink) flushAndClose() {
	s.flush()
	// Update session end_time.
	if s.db != nil {
		_, _ = s.db.Exec("UPDATE sessions SET end_time = ? WHERE session_id = ?",
			time.Now(), s.cfg.SessionID)
		s.db.Close()
	}
}

// Close flushes remaining events and closes the database.
func (s *DuckDBSink) Close() {
	s.flushAndClose()
}

func (s *DuckDBSink) insertBatch(batch *bufferedEvents) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	if err := insertProcessBatch(tx, batch.process); err != nil {
		tx.Rollback()
		return fmt.Errorf("process: %w", err)
	}
	if err := insertToolCallBatch(tx, batch.toolCall); err != nil {
		tx.Rollback()
		return fmt.Errorf("tool_call: %w", err)
	}
	if err := insertSystemBatch(tx, batch.system); err != nil {
		tx.Rollback()
		return fmt.Errorf("system: %w", err)
	}
	if err := insertSSLBatch(tx, batch.ssl); err != nil {
		tx.Rollback()
		return fmt.Errorf("ssl: %w", err)
	}
	if err := insertHTTPBatch(tx, batch.http); err != nil {
		tx.Rollback()
		return fmt.Errorf("http: %w", err)
	}
	if err := insertSSEBatch(tx, batch.sse); err != nil {
		tx.Rollback()
		return fmt.Errorf("sse: %w", err)
	}
	if err := insertSecurityBatch(tx, batch.security); err != nil {
		tx.Rollback()
		return fmt.Errorf("security: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	total := batch.total()
	logging.NamedZap("duckdb").Info("flushed events",
		zap.Int("rows", total),
		zap.String("session", s.cfg.SessionID),
	)
	return nil
}

// ---------- Per-table INSERT helpers ----------

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	s := "?"
	for i := 1; i < n; i++ {
		s += ", ?"
	}
	return s
}

func insertProcessBatch(tx *sql.Tx, rows []processRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 21
	stmt, err := tx.Prepare(`INSERT INTO events_process (
		session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		event_type, ppid, exit_code, duration_ms, filename, full_command,
		filepath, filepath2, file_flags, net_ip, net_port, net_family,
		dir_mode, bash_command, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		if _, err := stmt.Exec(
			r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.eventType, r.ppid, r.exitCode, r.durationMs, r.filename, r.fullCommand,
			r.filepath, r.filepath2, r.fileFlags, r.netIP, r.netPort, r.netFamily,
			r.dirMode, r.bashCommand, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertToolCallBatch(tx *sql.Tx, rows []toolCallRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 16
	stmt, err := tx.Prepare(`INSERT INTO events_tool_call (
		session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		tool_event_type, tool_name, tool_status, tool_reason, tool_bytes,
		tool_key_field, tool_args_hash, tool_tid, duration_ms, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		if _, err := stmt.Exec(
			r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.toolEventType, r.toolName, r.toolStatus, r.toolReason, r.toolBytes,
			r.toolKeyField, r.toolArgsHash, r.toolTID, r.durationMs, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertSystemBatch(tx *sql.Tx, rows []systemRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 15
	stmt, err := tx.Prepare(`INSERT INTO events_system (
		session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		sys_type, cpu_percent, cpu_cores, mem_rss_kb, mem_vsz_kb,
		thread_count, children_count, sys_alert, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		if _, err := stmt.Exec(
			r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.sysType, r.cpuPercent, r.cpuCores, r.memRssKB, r.memVszKB,
			r.threadCount, r.childrenCount, r.sysAlert, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertSSLBatch(tx *sql.Tx, rows []sslRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 12
	stmt, err := tx.Prepare(`INSERT INTO events_ssl (
		session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		ssl_function, ssl_len, ssl_is_handshake, ssl_latency_ms, ssl_tid, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		if _, err := stmt.Exec(
			r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.sslFunction, r.sslLen, r.sslIsHandshake, r.sslLatencyMs, r.sslTID, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertHTTPBatch(tx *sql.Tx, rows []httpRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 13
	stmt, err := tx.Prepare(`INSERT INTO events_http (
		session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		http_message_type, http_method, http_path, http_status_code,
		http_total_size, http_tid, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		if _, err := stmt.Exec(
			r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.httpMessageType, r.httpMethod, r.httpPath, r.httpStatusCode,
			r.httpTotalSize, r.httpTID, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertSSEBatch(tx *sql.Tx, rows []sseRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 11
	stmt, err := tx.Prepare(`INSERT INTO events_sse (
		session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		sse_connection_id, sse_duration_ns, sse_event_count, sse_total_size, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		if _, err := stmt.Exec(
			r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.sseConnectionID, r.sseDurationNs, r.sseEventCount, r.sseTotalSize, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertSecurityBatch(tx *sql.Tx, rows []securityRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 13
	stmt, err := tx.Prepare(`INSERT INTO events_security (
		session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		alert_type, risk_level, description, source_table,
		source_event_id, evidence_json, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		if _, err := stmt.Exec(
			r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.alertType, r.riskLevel, r.description, r.sourceTable,
			r.sourceEventID, r.evidenceJSON, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}
