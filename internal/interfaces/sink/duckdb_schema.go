package sink

// DDL statements for creating the DuckDB events table and analytics views.

const createSequenceSQL = `CREATE SEQUENCE IF NOT EXISTS event_id_seq START 1;`

const createEventsTableSQL = `
CREATE TABLE IF NOT EXISTS events (
    -- 通用字段（所有事件共有）
    id                  UBIGINT DEFAULT nextval('event_id_seq'),
    session_id          VARCHAR NOT NULL,
    timestamp_ns        BIGINT NOT NULL,
    timestamp_unix_ms   BIGINT,
    event_time          TIMESTAMP NOT NULL,
    source              VARCHAR NOT NULL,
    pid                 UINTEGER NOT NULL,
    comm                VARCHAR,

    -- process 事件提取字段
    event_type          VARCHAR,
    ppid                UINTEGER,
    exit_code           INTEGER,
    duration_ms         BIGINT,
    filename            VARCHAR,
    full_command        VARCHAR,
    filepath            VARCHAR,
    filepath2           VARCHAR,
    file_flags          UINTEGER,
    net_ip              VARCHAR,
    net_port            UINTEGER,
    net_family          UINTEGER,
    dir_mode            UINTEGER,
    bash_command        VARCHAR,

    -- tool_call 事件提取字段
    tool_event_type     VARCHAR,
    tool_name           VARCHAR,
    tool_status         VARCHAR,
    tool_reason         VARCHAR,
    tool_bytes          BIGINT,
    tool_key_field      VARCHAR,
    tool_args_hash      VARCHAR,
    tool_tid            UINTEGER,

    -- system 事件提取字段
    sys_type            VARCHAR,
    cpu_percent         DOUBLE,
    cpu_cores           UINTEGER,
    mem_rss_kb          UBIGINT,
    mem_vsz_kb          UBIGINT,
    thread_count        UINTEGER,
    children_count      UINTEGER,
    sys_alert           BOOLEAN,

    -- ssl 事件提取字段
    ssl_function        VARCHAR,
    ssl_len             UINTEGER,
    ssl_is_handshake    BOOLEAN,
    ssl_latency_ms      DOUBLE,
    ssl_tid             UINTEGER,

    -- http_parser 事件提取字段
    http_message_type   VARCHAR,
    http_method         VARCHAR,
    http_path           VARCHAR,
    http_status_code    USMALLINT,
    http_total_size     UINTEGER,
    http_tid            UINTEGER,

    -- sse_processor 事件提取字段
    sse_connection_id   VARCHAR,
    sse_duration_ns     BIGINT,
    sse_event_count     UINTEGER,
    sse_total_size      UINTEGER,

    -- 原始 JSON 数据
    data_json           JSON,

    -- 安全分析辅助字段（写入时计算）
    is_sensitive_file   BOOLEAN DEFAULT FALSE,
    is_dangerous_cmd    BOOLEAN DEFAULT FALSE
);
`

// Analytics views corresponding to data-analysis-dimensions.md.

const createViewSessionOverviewSQL = `
CREATE OR REPLACE VIEW v_session_overview AS
SELECT
    session_id,
    COUNT(*) AS total_events,
    MIN(event_time) AS first_event,
    MAX(event_time) AS last_event,
    AGE(MAX(event_time), MIN(event_time)) AS duration,
    COUNT(*) FILTER (WHERE source = 'tool_call') AS tool_call_events,
    COUNT(*) FILTER (WHERE source = 'process') AS process_events,
    COUNT(*) FILTER (WHERE source = 'system') AS system_events,
    COUNT(*) FILTER (WHERE source = 'ssl') AS ssl_events,
    COUNT(*) FILTER (WHERE source = 'http_parser') AS http_events,
    COUNT(*) FILTER (WHERE source = 'sse_processor') AS sse_events,
    COUNT(*) FILTER (WHERE source = 'stdio') AS stdio_events,
    COUNT(DISTINCT pid) AS unique_pids,
    COUNT(DISTINCT comm) AS unique_comms
FROM events
GROUP BY session_id;
`

const createViewToolCallStatsSQL = `
CREATE OR REPLACE VIEW v_tool_call_stats AS
SELECT
    session_id,
    tool_name,
    COUNT(*) FILTER (WHERE tool_event_type = 'tool_call_start') AS call_count,
    COUNT(*) FILTER (WHERE tool_event_type = 'tool_call_end' AND tool_status = 'success') AS success_count,
    COUNT(*) FILTER (WHERE tool_event_type = 'tool_call_end' AND tool_status = 'timeout') AS timeout_count,
    ROUND(
        COUNT(*) FILTER (WHERE tool_event_type = 'tool_call_end' AND tool_status = 'success') * 100.0 /
        NULLIF(COUNT(*) FILTER (WHERE tool_event_type = 'tool_call_end'), 0),
        2
    ) AS success_rate_pct,
    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE tool_event_type = 'tool_call_end' AND duration_ms IS NOT NULL) AS p50_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE tool_event_type = 'tool_call_end' AND duration_ms IS NOT NULL) AS p95_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE tool_event_type = 'tool_call_end' AND duration_ms IS NOT NULL) AS p99_ms,
    SUM(tool_bytes) FILTER (WHERE tool_event_type = 'tool_call_end') AS total_bytes
FROM events
WHERE source = 'tool_call'
GROUP BY session_id, tool_name;
`

const createViewProcessLifecycleSQL = `
CREATE OR REPLACE VIEW v_process_lifecycle AS
SELECT
    e.session_id,
    e.pid,
    e.comm,
    e.ppid,
    e.filename,
    e.full_command,
    e.event_time AS exec_time,
    x.event_time AS exit_time,
    x.exit_code,
    x.duration_ms,
    CASE WHEN x.exit_code IS NOT NULL AND x.exit_code != 0 THEN TRUE ELSE FALSE END AS abnormal_exit
FROM events e
LEFT JOIN events x ON e.session_id = x.session_id
    AND e.pid = x.pid
    AND x.source = 'process'
    AND x.event_type = 'EXIT'
WHERE e.source = 'process' AND e.event_type = 'EXEC';
`

const createViewSecurityAlertsSQL = `
CREATE OR REPLACE VIEW v_security_alerts AS
SELECT
    session_id,
    event_time,
    pid,
    comm,
    CASE
        WHEN is_dangerous_cmd THEN 'dangerous_command'
        WHEN is_sensitive_file AND event_type IN ('FILE_OPEN', 'FILE_DELETE', 'FILE_RENAME') THEN 'sensitive_file_access'
        WHEN source = 'process' AND event_type = 'NET_CONNECT' AND net_port NOT IN (80, 443, 8080, 8443) THEN 'unusual_port'
        WHEN source = 'process' AND event_type = 'DIR_CREATE' AND dir_mode = 511 THEN 'permissive_directory'
        WHEN source = 'process' AND event_type = 'CRED_CHANGE' THEN 'credential_change'
        WHEN source = 'process' AND event_type = 'EXIT' AND exit_code != 0 THEN 'abnormal_exit'
    END AS alert_type,
    COALESCE(full_command, filepath, net_ip || ':' || CAST(net_port AS VARCHAR), '') AS detail,
    source,
    event_type,
    data_json
FROM events
WHERE is_dangerous_cmd
   OR (is_sensitive_file AND event_type IN ('FILE_OPEN', 'FILE_DELETE', 'FILE_RENAME'))
   OR (source = 'process' AND event_type = 'NET_CONNECT' AND net_port NOT IN (80, 443, 8080, 8443))
   OR (source = 'process' AND event_type = 'DIR_CREATE' AND dir_mode = 511)
   OR (source = 'process' AND event_type = 'CRED_CHANGE')
   OR (source = 'process' AND event_type = 'EXIT' AND exit_code != 0);
`

const createViewResourceTimeseriesSQL = `
CREATE OR REPLACE VIEW v_resource_timeseries AS
SELECT
    session_id,
    TIME_BUCKET(INTERVAL '5 seconds', event_time) AS bucket,
    pid,
    comm,
    AVG(cpu_percent) AS avg_cpu_percent,
    MAX(cpu_percent) AS max_cpu_percent,
    AVG(mem_rss_kb) AS avg_mem_rss_kb,
    MAX(mem_rss_kb) AS max_mem_rss_kb,
    AVG(mem_vsz_kb) AS avg_mem_vsz_kb,
    AVG(thread_count) AS avg_threads,
    MAX(thread_count) AS max_threads,
    COUNT(*) AS sample_count,
    BOOL_OR(sys_alert) AS has_alert
FROM events
WHERE source = 'system'
GROUP BY session_id, bucket, pid, comm
ORDER BY bucket;
`

const createViewNetworkAnalysisSQL = `
CREATE OR REPLACE VIEW v_network_analysis AS
SELECT
    session_id,
    net_ip,
    net_port,
    net_family,
    COUNT(*) AS connection_count,
    COUNT(DISTINCT pid) AS unique_pids,
    MIN(event_time) AS first_seen,
    MAX(event_time) AS last_seen,
    LIST(DISTINCT comm) AS comms
FROM events
WHERE source = 'process' AND event_type = 'NET_CONNECT'
GROUP BY session_id, net_ip, net_port, net_family
ORDER BY connection_count DESC;
`

const createViewHotFilesSQL = `
CREATE OR REPLACE VIEW v_hot_files AS
SELECT
    session_id,
    COALESCE(filepath, tool_key_field) AS file_path,
    COUNT(*) AS access_count,
    COUNT(*) FILTER (WHERE source = 'tool_call' AND tool_name = 'fs.read') AS read_count,
    COUNT(*) FILTER (WHERE source = 'tool_call' AND tool_name = 'fs.write') AS write_count,
    COUNT(*) FILTER (WHERE source = 'process' AND event_type = 'FILE_OPEN') AS open_count,
    COUNT(*) FILTER (WHERE source = 'process' AND event_type = 'FILE_DELETE') AS delete_count,
    SUM(tool_bytes) AS total_bytes,
    BOOL_OR(is_sensitive_file) AS is_sensitive
FROM events
WHERE COALESCE(filepath, tool_key_field) IS NOT NULL
GROUP BY session_id, COALESCE(filepath, tool_key_field)
ORDER BY access_count DESC;
`

const createViewExfiltrationRiskSQL = `
CREATE OR REPLACE VIEW v_exfiltration_risk AS
SELECT
    f.session_id,
    f.event_time AS file_access_time,
    f.pid AS file_pid,
    f.comm AS file_comm,
    COALESCE(f.filepath, f.tool_key_field) AS sensitive_file,
    n.event_time AS network_time,
    n.pid AS net_pid,
    n.comm AS net_comm,
    n.net_ip,
    n.net_port,
    AGE(n.event_time, f.event_time) AS time_gap
FROM events f
JOIN events n ON f.session_id = n.session_id
    AND n.source = 'process'
    AND n.event_type = 'NET_CONNECT'
    AND n.event_time > f.event_time
    AND n.event_time <= f.event_time + INTERVAL '30 seconds'
WHERE f.is_sensitive_file
  AND f.event_type IN ('FILE_OPEN', 'FILE_DELETE', 'FILE_RENAME')
ORDER BY f.event_time;
`

// allSchemaSQL returns DDL statements in creation order.
var allSchemaSQL = []string{
	createSequenceSQL,
	createEventsTableSQL,
	createViewSessionOverviewSQL,
	createViewToolCallStatsSQL,
	createViewProcessLifecycleSQL,
	createViewSecurityAlertsSQL,
	createViewResourceTimeseriesSQL,
	createViewNetworkAnalysisSQL,
	createViewHotFilesSQL,
	createViewExfiltrationRiskSQL,
}
