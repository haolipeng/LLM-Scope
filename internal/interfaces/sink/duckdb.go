package sink

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	_ "github.com/marcboeker/go-duckdb"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
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

// DuckDBSink implements pipelinetypes.Sink and writes events into a DuckDB
// database using batched inserts.
type DuckDBSink struct {
	db        *sql.DB
	cfg       DuckDBConfig
	mu        sync.Mutex
	buffer    []eventRow
	insertSQL string
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

	s := &DuckDBSink{
		db:     db,
		cfg:    cfg,
		buffer: make([]eventRow, 0, cfg.BatchSize),
	}
	s.insertSQL = buildInsertSQL()
	return s, nil
}

func (s *DuckDBSink) Name() string { return "duckdb" }

// DB exposes the underlying connection for analytics queries.
func (s *DuckDBSink) DB() *sql.DB { return s.db }

// Consume reads events from the channel and writes them to DuckDB in batches.
func (s *DuckDBSink) Consume(ctx context.Context, in <-chan *runtimeevent.Event) {
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

func (s *DuckDBSink) addEvent(event *runtimeevent.Event) {
	row := extractRow(event, s.cfg.SessionID)
	s.mu.Lock()
	s.buffer = append(s.buffer, row)
	needFlush := len(s.buffer) >= s.cfg.BatchSize
	s.mu.Unlock()

	if needFlush {
		s.flush()
	}
}

func (s *DuckDBSink) flush() {
	s.mu.Lock()
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.buffer
	s.buffer = make([]eventRow, 0, s.cfg.BatchSize)
	s.mu.Unlock()

	if err := s.insertBatch(batch); err != nil {
		fmt.Fprintf(os.Stderr, "duckdb: flush error (%d rows): %v\n", len(batch), err)
	}
}

func (s *DuckDBSink) flushAndClose() {
	s.flush()
	if s.db != nil {
		s.db.Close()
	}
}

// Close flushes remaining events and closes the database.
func (s *DuckDBSink) Close() {
	s.flushAndClose()
}

func (s *DuckDBSink) insertBatch(batch []eventRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	stmt, err := tx.Prepare(s.insertSQL)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for i := range batch {
		r := &batch[i]
		_, err := stmt.Exec(
			r.sessionID,
			r.timestampNs,
			r.timestampUnix,
			r.eventTime,
			r.source,
			r.pid,
			r.comm,
			// process
			r.eventType,
			r.ppid,
			r.exitCode,
			r.durationMs,
			r.filename,
			r.fullCommand,
			r.filepath,
			r.filepath2,
			r.fileFlags,
			r.netIP,
			r.netPort,
			r.netFamily,
			r.dirMode,
			r.bashCommand,
			// tool_call
			r.toolEventType,
			r.toolName,
			r.toolStatus,
			r.toolReason,
			r.toolBytes,
			r.toolKeyField,
			r.toolArgsHash,
			r.toolTID,
			// system
			r.sysType,
			r.cpuPercent,
			r.cpuCores,
			r.memRssKB,
			r.memVszKB,
			r.threadCount,
			r.childrenCount,
			r.sysAlert,
			// ssl
			r.sslFunction,
			r.sslLen,
			r.sslIsHandshake,
			r.sslLatencyMs,
			r.sslTID,
			// http_parser
			r.httpMessageType,
			r.httpMethod,
			r.httpPath,
			r.httpStatusCode,
			r.httpTotalSize,
			r.httpTID,
			// sse_processor
			r.sseConnectionID,
			r.sseDurationNs,
			r.sseEventCount,
			r.sseTotalSize,
			// json + security
			r.dataJSON,
			r.isSensitiveFile,
			r.isDangerousCmd,
		)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("exec row %d: %w", i, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	log.Printf("duckdb: flushed %d events (session=%s)", len(batch), s.cfg.SessionID)
	return nil
}

func buildInsertSQL() string {
	const cols = 55 // total columns being inserted
	placeholders := "?"
	for i := 1; i < cols; i++ {
		placeholders += ", ?"
	}
	return `INSERT INTO events (
		session_id, timestamp_ns, timestamp_unix_ms, event_time, source, pid, comm,
		event_type, ppid, exit_code, duration_ms, filename, full_command,
		filepath, filepath2, file_flags, net_ip, net_port, net_family, dir_mode, bash_command,
		tool_event_type, tool_name, tool_status, tool_reason, tool_bytes,
		tool_key_field, tool_args_hash, tool_tid,
		sys_type, cpu_percent, cpu_cores, mem_rss_kb, mem_vsz_kb,
		thread_count, children_count, sys_alert,
		ssl_function, ssl_len, ssl_is_handshake, ssl_latency_ms, ssl_tid,
		http_message_type, http_method, http_path, http_status_code, http_total_size, http_tid,
		sse_connection_id, sse_duration_ns, sse_event_count, sse_total_size,
		data_json, is_sensitive_file, is_dangerous_cmd
	) VALUES (` + placeholders + `)`
}
