package sink

// DDL statements for creating the DuckDB multi-table schema.
// Tables are split by event source for clean, compact schemas.

const createSequenceSQL = `CREATE SEQUENCE IF NOT EXISTS event_id_seq START 1;`

const createSessionsTableSQL = `
CREATE TABLE IF NOT EXISTS sessions (
    session_id      VARCHAR PRIMARY KEY,
    start_time      TIMESTAMP,
    end_time        TIMESTAMP,
    comm_filter     VARCHAR,
    binary_path     VARCHAR,
    hostname        VARCHAR,
    kernel_version  VARCHAR,
    labels          JSON
);
`

const createEventsProcessTableSQL = `
CREATE TABLE IF NOT EXISTS events_process (
    id              UBIGINT DEFAULT nextval('event_id_seq'),
    session_id      VARCHAR NOT NULL,
    timestamp_ns    BIGINT NOT NULL,
    timestamp_unix_ms BIGINT,
    event_time      TIMESTAMP NOT NULL,
    pid             UINTEGER NOT NULL,
    comm            VARCHAR,
    event_type      VARCHAR,
    ppid            UINTEGER,
    exit_code       INTEGER,
    duration_ms     BIGINT,
    filename        VARCHAR,
    full_command    VARCHAR,
    filepath        VARCHAR,
    filepath2       VARCHAR,
    file_flags      UINTEGER,
    net_ip          VARCHAR,
    net_port        UINTEGER,
    net_family      UINTEGER,
    dir_mode        UINTEGER,
    bash_command    VARCHAR,
    data_json       JSON
);
`

const createEventsToolCallTableSQL = `
CREATE TABLE IF NOT EXISTS events_tool_call (
    id              UBIGINT DEFAULT nextval('event_id_seq'),
    session_id      VARCHAR NOT NULL,
    timestamp_ns    BIGINT NOT NULL,
    timestamp_unix_ms BIGINT,
    event_time      TIMESTAMP NOT NULL,
    pid             UINTEGER NOT NULL,
    comm            VARCHAR,
    tool_event_type VARCHAR,
    tool_name       VARCHAR,
    tool_status     VARCHAR,
    tool_reason     VARCHAR,
    tool_bytes      BIGINT,
    tool_key_field  VARCHAR,
    tool_args_hash  VARCHAR,
    tool_tid        UINTEGER,
    duration_ms     BIGINT,
    data_json       JSON
);
`

const createEventsSystemTableSQL = `
CREATE TABLE IF NOT EXISTS events_system (
    id              UBIGINT DEFAULT nextval('event_id_seq'),
    session_id      VARCHAR NOT NULL,
    timestamp_ns    BIGINT NOT NULL,
    timestamp_unix_ms BIGINT,
    event_time      TIMESTAMP NOT NULL,
    pid             UINTEGER NOT NULL,
    comm            VARCHAR,
    sys_type        VARCHAR,
    cpu_percent     DOUBLE,
    cpu_cores       UINTEGER,
    mem_rss_kb      UBIGINT,
    mem_vsz_kb      UBIGINT,
    thread_count    UINTEGER,
    children_count  UINTEGER,
    sys_alert       BOOLEAN,
    data_json       JSON
);
`

const createEventsSSLTableSQL = `
CREATE TABLE IF NOT EXISTS events_ssl (
    id              UBIGINT DEFAULT nextval('event_id_seq'),
    session_id      VARCHAR NOT NULL,
    timestamp_ns    BIGINT NOT NULL,
    timestamp_unix_ms BIGINT,
    event_time      TIMESTAMP NOT NULL,
    pid             UINTEGER NOT NULL,
    comm            VARCHAR,
    ssl_function    VARCHAR,
    ssl_len         UINTEGER,
    ssl_is_handshake BOOLEAN,
    ssl_latency_ms  DOUBLE,
    ssl_tid         UINTEGER,
    data_json       JSON
);
`

const createEventsHTTPTableSQL = `
CREATE TABLE IF NOT EXISTS events_http (
    id              UBIGINT DEFAULT nextval('event_id_seq'),
    session_id      VARCHAR NOT NULL,
    timestamp_ns    BIGINT NOT NULL,
    timestamp_unix_ms BIGINT,
    event_time      TIMESTAMP NOT NULL,
    pid             UINTEGER NOT NULL,
    comm            VARCHAR,
    http_message_type VARCHAR,
    http_method     VARCHAR,
    http_path       VARCHAR,
    http_status_code USMALLINT,
    http_total_size UINTEGER,
    http_tid        UINTEGER,
    data_json       JSON
);
`

const createEventsSSETableSQL = `
CREATE TABLE IF NOT EXISTS events_sse (
    id              UBIGINT DEFAULT nextval('event_id_seq'),
    session_id      VARCHAR NOT NULL,
    timestamp_ns    BIGINT NOT NULL,
    timestamp_unix_ms BIGINT,
    event_time      TIMESTAMP NOT NULL,
    pid             UINTEGER NOT NULL,
    comm            VARCHAR,
    sse_connection_id VARCHAR,
    sse_duration_ns  BIGINT,
    sse_event_count  UINTEGER,
    sse_total_size   UINTEGER,
    data_json        JSON
);
`

const createEventsSecurityTableSQL = `
CREATE TABLE IF NOT EXISTS events_security (
    id              UBIGINT DEFAULT nextval('event_id_seq'),
    session_id      VARCHAR NOT NULL,
    timestamp_ns    BIGINT NOT NULL,
    timestamp_unix_ms BIGINT,
    event_time      TIMESTAMP NOT NULL,
    pid             UINTEGER NOT NULL,
    comm            VARCHAR,
    alert_type      VARCHAR,
    risk_level      VARCHAR,
    description     VARCHAR,
    source_table    VARCHAR,
    source_event_id UBIGINT,
    evidence_json   JSON,
    data_json       JSON
);
`

const createProcessTreeTableSQL = `
CREATE TABLE IF NOT EXISTS process_tree (
    session_id  VARCHAR NOT NULL,
    pid         UINTEGER NOT NULL,
    ppid        UINTEGER,
    comm        VARCHAR,
    filename    VARCHAR,
    start_time  TIMESTAMP,
    end_time    TIMESTAMP,
    depth       UINTEGER,
    PRIMARY KEY (session_id, pid)
);
`

const createEventLinksTableSQL = `
CREATE TABLE IF NOT EXISTS event_links (
    session_id      VARCHAR NOT NULL,
    source_table    VARCHAR NOT NULL,
    source_id       UBIGINT NOT NULL,
    target_table    VARCHAR NOT NULL,
    target_id       UBIGINT NOT NULL,
    link_type       VARCHAR NOT NULL
);
`

// Analytics views that query across the split tables.

const createViewSessionOverviewSQL = `
CREATE OR REPLACE VIEW v_session_overview AS
WITH counts AS (
    SELECT session_id, 'tool_call' AS source, COUNT(*) AS cnt, COUNT(DISTINCT pid) AS pids, COUNT(DISTINCT comm) AS comms FROM events_tool_call GROUP BY session_id
    UNION ALL
    SELECT session_id, 'process', COUNT(*), COUNT(DISTINCT pid), COUNT(DISTINCT comm) FROM events_process GROUP BY session_id
    UNION ALL
    SELECT session_id, 'system', COUNT(*), COUNT(DISTINCT pid), COUNT(DISTINCT comm) FROM events_system GROUP BY session_id
    UNION ALL
    SELECT session_id, 'ssl', COUNT(*), COUNT(DISTINCT pid), COUNT(DISTINCT comm) FROM events_ssl GROUP BY session_id
    UNION ALL
    SELECT session_id, 'http', COUNT(*), COUNT(DISTINCT pid), COUNT(DISTINCT comm) FROM events_http GROUP BY session_id
    UNION ALL
    SELECT session_id, 'sse', COUNT(*), COUNT(DISTINCT pid), COUNT(DISTINCT comm) FROM events_sse GROUP BY session_id
    UNION ALL
    SELECT session_id, 'security', COUNT(*), COUNT(DISTINCT pid), COUNT(DISTINCT comm) FROM events_security GROUP BY session_id
),
times AS (
    SELECT session_id, MIN(event_time) AS et, MAX(event_time) AS lt FROM events_process GROUP BY session_id
    UNION ALL
    SELECT session_id, MIN(event_time), MAX(event_time) FROM events_tool_call GROUP BY session_id
    UNION ALL
    SELECT session_id, MIN(event_time), MAX(event_time) FROM events_system GROUP BY session_id
    UNION ALL
    SELECT session_id, MIN(event_time), MAX(event_time) FROM events_ssl GROUP BY session_id
    UNION ALL
    SELECT session_id, MIN(event_time), MAX(event_time) FROM events_http GROUP BY session_id
    UNION ALL
    SELECT session_id, MIN(event_time), MAX(event_time) FROM events_sse GROUP BY session_id
    UNION ALL
    SELECT session_id, MIN(event_time), MAX(event_time) FROM events_security GROUP BY session_id
)
SELECT
    c.session_id,
    SUM(c.cnt) AS total_events,
    MIN(t.et) AS first_event,
    MAX(t.lt) AS last_event,
    AGE(MAX(t.lt), MIN(t.et)) AS duration,
    SUM(c.cnt) FILTER (WHERE c.source = 'tool_call') AS tool_call_events,
    SUM(c.cnt) FILTER (WHERE c.source = 'process') AS process_events,
    SUM(c.cnt) FILTER (WHERE c.source = 'system') AS system_events,
    SUM(c.cnt) FILTER (WHERE c.source = 'ssl') AS ssl_events,
    SUM(c.cnt) FILTER (WHERE c.source = 'http') AS http_events,
    SUM(c.cnt) FILTER (WHERE c.source = 'sse') AS sse_events,
    SUM(c.cnt) FILTER (WHERE c.source = 'security') AS security_events
FROM counts c
JOIN times t ON c.session_id = t.session_id
GROUP BY c.session_id;
`

const createViewToolCallStatsSQL = `
CREATE OR REPLACE VIEW v_tool_call_stats AS
SELECT
    session_id,
    tool_name,
    COUNT(*) AS call_count,
    COUNT(*) FILTER (WHERE tool_status = 'success') AS success_count,
    COUNT(*) FILTER (WHERE tool_status = 'timeout') AS timeout_count,
    ROUND(
        COUNT(*) FILTER (WHERE tool_status = 'success') * 100.0 /
        NULLIF(COUNT(*), 0),
        2
    ) AS success_rate_pct,
    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS p50_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS p95_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS p99_ms,
    SUM(tool_bytes) AS total_bytes
FROM events_tool_call
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
FROM events_process e
LEFT JOIN events_process x ON e.session_id = x.session_id
    AND e.pid = x.pid
    AND x.event_type = 'EXIT'
WHERE e.event_type = 'EXEC';
`

const createViewSecurityAlertsSQL = `
CREATE OR REPLACE VIEW v_security_alerts AS
SELECT
    id,
    session_id,
    event_time,
    pid,
    comm,
    alert_type,
    risk_level,
    description,
    source_table,
    source_event_id,
    evidence_json,
    data_json
FROM events_security
ORDER BY event_time DESC;
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
FROM events_system
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
FROM events_process
WHERE event_type = 'NET_CONNECT'
GROUP BY session_id, net_ip, net_port, net_family
ORDER BY connection_count DESC;
`

const createViewHotFilesSQL = `
CREATE OR REPLACE VIEW v_hot_files AS
WITH file_access AS (
    SELECT session_id, filepath AS file_path, 'open' AS op FROM events_process WHERE event_type = 'FILE_OPEN' AND filepath IS NOT NULL
    UNION ALL
    SELECT session_id, filepath AS file_path, 'delete' AS op FROM events_process WHERE event_type = 'FILE_DELETE' AND filepath IS NOT NULL
    UNION ALL
    SELECT session_id, tool_key_field AS file_path, CASE WHEN tool_name = 'fs.read' THEN 'read' ELSE 'write' END AS op
    FROM events_tool_call WHERE tool_key_field IS NOT NULL AND tool_name IN ('fs.read', 'fs.write')
)
SELECT
    session_id,
    file_path,
    COUNT(*) AS access_count,
    COUNT(*) FILTER (WHERE op = 'read') AS read_count,
    COUNT(*) FILTER (WHERE op = 'write') AS write_count,
    COUNT(*) FILTER (WHERE op = 'open') AS open_count,
    COUNT(*) FILTER (WHERE op = 'delete') AS delete_count
FROM file_access
GROUP BY session_id, file_path
ORDER BY access_count DESC;
`

const createViewExfiltrationRiskSQL = `
CREATE OR REPLACE VIEW v_exfiltration_risk AS
SELECT
    s.session_id,
    s.event_time AS alert_time,
    s.pid,
    s.comm,
    s.alert_type,
    s.risk_level,
    s.description,
    s.evidence_json
FROM events_security s
WHERE s.alert_type IN ('sensitive_file_access', 'exfiltration_risk')
ORDER BY s.event_time;
`

// allSchemaSQL returns DDL statements in creation order.
var allSchemaSQL = []string{
	createSequenceSQL,
	createSessionsTableSQL,
	createEventsProcessTableSQL,
	createEventsToolCallTableSQL,
	createEventsSystemTableSQL,
	createEventsSSLTableSQL,
	createEventsHTTPTableSQL,
	createEventsSSETableSQL,
	createEventsSecurityTableSQL,
	createProcessTreeTableSQL,
	createEventLinksTableSQL,
	createViewSessionOverviewSQL,
	createViewToolCallStatsSQL,
	createViewProcessLifecycleSQL,
	createViewSecurityAlertsSQL,
	createViewResourceTimeseriesSQL,
	createViewNetworkAnalysisSQL,
	createViewHotFilesSQL,
	createViewExfiltrationRiskSQL,
}
