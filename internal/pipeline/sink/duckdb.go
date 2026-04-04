package sink

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"syscall"
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
	CommFilter    string        // --comm flag value
	BinaryPath    string        // --binary-path flag value
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
		c.SessionID = fmt.Sprintf("%s-%d", time.Now().Format("20060102-150405"), os.Getpid())
	}
}

// bufferedEvents holds events grouped by source for batch insertion.
type bufferedEvents struct {
	process     []processRow
	toolCall    []toolCallRow
	system      []systemRow
	ssl         []sslRow
	http        []httpRow
	sse         []sseRow
	security    []securityRow
	processTree []processTreeRow
	eventLinks  []eventLinkRow
}

func (b *bufferedEvents) total() int {
	return len(b.process) + len(b.toolCall) + len(b.system) +
		len(b.ssl) + len(b.http) + len(b.sse) + len(b.security) +
		len(b.processTree) + len(b.eventLinks)
}

func (b *bufferedEvents) reset() {
	b.process = b.process[:0]
	b.toolCall = b.toolCall[:0]
	b.system = b.system[:0]
	b.ssl = b.ssl[:0]
	b.http = b.http[:0]
	b.sse = b.sse[:0]
	b.security = b.security[:0]
	b.processTree = b.processTree[:0]
	b.eventLinks = b.eventLinks[:0]
}

// DuckDBSink implements pipelinetypes.Sink and writes events into a DuckDB
// database using batched inserts into per-source tables.
type DuckDBSink struct {
	db         *sql.DB
	cfg        DuckDBConfig
	mu         sync.Mutex
	buf        bufferedEvents
	streamToID map[uint64]uint64 // session-level StreamSeq → DB ID mapping
	seenPIDs   map[uint32]bool   // tracks PIDs already inserted into process_tree
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
	hostname, _ := os.Hostname()
	kernelVersion := getKernelVersion()
	_, _ = db.Exec(
		`INSERT INTO sessions (session_id, start_time, comm_filter, binary_path, hostname, kernel_version)
		 VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
		cfg.SessionID, time.Now(), nilIfEmpty(cfg.CommFilter), nilIfEmpty(cfg.BinaryPath),
		hostname, kernelVersion,
	)

	s := &DuckDBSink{
		db:         db,
		cfg:        cfg,
		streamToID: make(map[uint64]uint64),
		seenPIDs:   make(map[uint32]bool),
	}
	return s, nil
}

func (s *DuckDBSink) Name() string { return "duckdb" }

// getKernelVersion returns the OS kernel release string.
func getKernelVersion() string {
	var buf syscall.Utsname
	if err := syscall.Uname(&buf); err != nil {
		return ""
	}
	b := make([]byte, 0, len(buf.Release))
	for _, c := range buf.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// nilIfEmpty returns nil for empty strings, or a pointer to s.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

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

func (s *DuckDBSink) addEvent(e *event.Event) {
	// Skip tool_call_start events (only persist tool_call_end).
	if e.Source == "tool_call" && bytes.Contains(e.Data, toolCallStartPrefix) {
		return
	}

	if e.StreamSeq == 0 {
		e.StreamSeq = event.NextStreamSeq()
	}

	s.mu.Lock()
	switch e.Source {
	case "process":
		s.buf.process = append(s.buf.process, extractProcessRow(e, s.cfg.SessionID))
		// Build process_tree from EXEC events (one row per unique PID).
		if row, ok := extractProcessTreeRow(e, s.cfg.SessionID); ok {
			if !s.seenPIDs[row.pid] {
				s.seenPIDs[row.pid] = true
				s.buf.processTree = append(s.buf.processTree, row)
			}
		}
	case "tool_call":
		s.buf.toolCall = append(s.buf.toolCall, extractToolCallRow(e, s.cfg.SessionID))
	case "system":
		s.buf.system = append(s.buf.system, extractSystemRow(e, s.cfg.SessionID))
	case "ssl":
		s.buf.ssl = append(s.buf.ssl, extractSSLRow(e, s.cfg.SessionID))
	case "http_parser":
		s.buf.http = append(s.buf.http, extractHTTPRow(e, s.cfg.SessionID))
	case "sse_processor":
		s.buf.sse = append(s.buf.sse, extractSSERow(e, s.cfg.SessionID))
	case "security":
		s.buf.security = append(s.buf.security, extractSecurityRow(e, s.cfg.SessionID))
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

	nextID := func() (uint64, error) {
		var id uint64
		err := tx.QueryRow("SELECT nextval('event_id_seq')").Scan(&id)
		return id, err
	}

	if err := insertProcessBatch(tx, batch.process, s.streamToID, nextID); err != nil {
		tx.Rollback()
		return fmt.Errorf("process: %w", err)
	}
	if err := insertToolCallBatch(tx, batch.toolCall, s.streamToID, nextID); err != nil {
		tx.Rollback()
		return fmt.Errorf("tool_call: %w", err)
	}
	if err := insertSystemBatch(tx, batch.system, s.streamToID, nextID); err != nil {
		tx.Rollback()
		return fmt.Errorf("system: %w", err)
	}
	if err := insertSSLBatch(tx, batch.ssl, s.streamToID, nextID); err != nil {
		tx.Rollback()
		return fmt.Errorf("ssl: %w", err)
	}
	if err := insertHTTPBatch(tx, batch.http, s.streamToID, nextID); err != nil {
		tx.Rollback()
		return fmt.Errorf("http: %w", err)
	}
	if err := insertSSEBatch(tx, batch.sse, s.streamToID, nextID); err != nil {
		tx.Rollback()
		return fmt.Errorf("sse: %w", err)
	}
	if err := insertSecurityBatch(tx, batch.security, s.streamToID); err != nil {
		tx.Rollback()
		return fmt.Errorf("security: %w", err)
	}
	if err := insertProcessTreeBatch(tx, batch.processTree); err != nil {
		tx.Rollback()
		return fmt.Errorf("process_tree: %w", err)
	}
	if err := insertEventLinksBatch(tx, batch.eventLinks); err != nil {
		tx.Rollback()
		return fmt.Errorf("event_links: %w", err)
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

func insertProcessBatch(tx *sql.Tx, rows []processRow, streamToID map[uint64]uint64, nextID func() (uint64, error)) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 22
	stmt, err := tx.Prepare(`INSERT INTO events_process (
		id, session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
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
		id, err := nextID()
		if err != nil {
			return fmt.Errorf("row %d nextval: %w", i, err)
		}
		if r.streamSeq != 0 {
			streamToID[r.streamSeq] = id
		}
		if _, err := stmt.Exec(
			id, r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.eventType, r.ppid, r.exitCode, r.durationMs, r.filename, r.fullCommand,
			r.filepath, r.filepath2, r.fileFlags, r.netIP, r.netPort, r.netFamily,
			r.dirMode, r.bashCommand, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertToolCallBatch(tx *sql.Tx, rows []toolCallRow, streamToID map[uint64]uint64, nextID func() (uint64, error)) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 17
	stmt, err := tx.Prepare(`INSERT INTO events_tool_call (
		id, session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		tool_event_type, tool_name, tool_status, tool_reason, tool_bytes,
		tool_key_field, tool_args_hash, tool_tid, duration_ms, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		id, err := nextID()
		if err != nil {
			return fmt.Errorf("row %d nextval: %w", i, err)
		}
		if r.streamSeq != 0 {
			streamToID[r.streamSeq] = id
		}
		if _, err := stmt.Exec(
			id, r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.toolEventType, r.toolName, r.toolStatus, r.toolReason, r.toolBytes,
			r.toolKeyField, r.toolArgsHash, r.toolTID, r.durationMs, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertSystemBatch(tx *sql.Tx, rows []systemRow, streamToID map[uint64]uint64, nextID func() (uint64, error)) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 16
	stmt, err := tx.Prepare(`INSERT INTO events_system (
		id, session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		sys_type, cpu_percent, cpu_cores, mem_rss_kb, mem_vsz_kb,
		thread_count, children_count, sys_alert, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		id, err := nextID()
		if err != nil {
			return fmt.Errorf("row %d nextval: %w", i, err)
		}
		if r.streamSeq != 0 {
			streamToID[r.streamSeq] = id
		}
		if _, err := stmt.Exec(
			id, r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.sysType, r.cpuPercent, r.cpuCores, r.memRssKB, r.memVszKB,
			r.threadCount, r.childrenCount, r.sysAlert, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertSSLBatch(tx *sql.Tx, rows []sslRow, streamToID map[uint64]uint64, nextID func() (uint64, error)) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 13
	stmt, err := tx.Prepare(`INSERT INTO events_ssl (
		id, session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		ssl_function, ssl_len, ssl_is_handshake, ssl_latency_ms, ssl_tid, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		id, err := nextID()
		if err != nil {
			return fmt.Errorf("row %d nextval: %w", i, err)
		}
		if r.streamSeq != 0 {
			streamToID[r.streamSeq] = id
		}
		if _, err := stmt.Exec(
			id, r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.sslFunction, r.sslLen, r.sslIsHandshake, r.sslLatencyMs, r.sslTID, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertHTTPBatch(tx *sql.Tx, rows []httpRow, streamToID map[uint64]uint64, nextID func() (uint64, error)) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 14
	stmt, err := tx.Prepare(`INSERT INTO events_http (
		id, session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		http_message_type, http_method, http_path, http_status_code,
		http_total_size, http_tid, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		id, err := nextID()
		if err != nil {
			return fmt.Errorf("row %d nextval: %w", i, err)
		}
		if r.streamSeq != 0 {
			streamToID[r.streamSeq] = id
		}
		if _, err := stmt.Exec(
			id, r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.httpMessageType, r.httpMethod, r.httpPath, r.httpStatusCode,
			r.httpTotalSize, r.httpTID, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertSSEBatch(tx *sql.Tx, rows []sseRow, streamToID map[uint64]uint64, nextID func() (uint64, error)) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 12
	stmt, err := tx.Prepare(`INSERT INTO events_sse (
		id, session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		sse_connection_id, sse_duration_ns, sse_event_count, sse_total_size, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		id, err := nextID()
		if err != nil {
			return fmt.Errorf("row %d nextval: %w", i, err)
		}
		if r.streamSeq != 0 {
			streamToID[r.streamSeq] = id
		}
		if _, err := stmt.Exec(
			id, r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.sseConnectionID, r.sseDurationNs, r.sseEventCount, r.sseTotalSize, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertSecurityBatch(tx *sql.Tx, rows []securityRow, streamToID map[uint64]uint64) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 14
	stmt, err := tx.Prepare(`INSERT INTO events_security (
		id, session_id, timestamp_ns, timestamp_unix_ms, event_time, pid, comm,
		alert_type, risk_level, description, source_table,
		source_event_id, evidence_json, data_json
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	nextID := func() (uint64, error) {
		var id uint64
		err := tx.QueryRow("SELECT nextval('event_id_seq')").Scan(&id)
		return id, err
	}

	for i := range rows {
		r := &rows[i]
		if r.sourceStreamSeq != 0 {
			if srcID, ok := streamToID[r.sourceStreamSeq]; ok {
				v := srcID
				r.sourceEventID = &v
			}
		}
		id, err := nextID()
		if err != nil {
			return fmt.Errorf("row %d nextval: %w", i, err)
		}
		if r.streamSeq != 0 {
			streamToID[r.streamSeq] = id
		}
		if _, err := stmt.Exec(
			id, r.sessionID, r.timestampNs, r.timestampUnix, r.eventTime, r.pid, r.comm,
			r.alertType, r.riskLevel, r.description, r.sourceTable,
			r.sourceEventID, r.evidenceJSON, r.dataJSON,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertProcessTreeBatch(tx *sql.Tx, rows []processTreeRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 7
	stmt, err := tx.Prepare(`INSERT INTO process_tree (
		session_id, pid, ppid, comm, filename, start_time, depth
	) VALUES (` + placeholders(cols) + `) ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		if _, err := stmt.Exec(
			r.sessionID, r.pid, r.ppid, r.comm, r.filename, r.startTime, r.depth,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

func insertEventLinksBatch(tx *sql.Tx, rows []eventLinkRow) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 6
	stmt, err := tx.Prepare(`INSERT INTO event_links (
		session_id, source_table, source_id, target_table, target_id, link_type
	) VALUES (` + placeholders(cols) + `)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range rows {
		r := &rows[i]
		if _, err := stmt.Exec(
			r.sessionID, r.sourceTable, r.sourceID, r.targetTable, r.targetID, r.linkType,
		); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}
