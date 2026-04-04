package httpserver

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/haolipeng/LLM-Scope/internal/logging"
	"go.uber.org/zap"
)

// registerAnalyticsRoutes adds the /api/analytics route group.
func registerAnalyticsRoutes(api *gin.RouterGroup, db *sql.DB) {
	analytics := api.Group("/analytics")
	{
		analytics.POST("/query", handleQuery(db))
		analytics.GET("/overview", handleView(db, "SELECT * FROM v_session_overview"))
		analytics.GET("/tool-calls/stats", handleView(db, "SELECT * FROM v_tool_call_stats"))
		analytics.GET("/tool-calls/latency", handleToolCallLatency(db))
		analytics.GET("/process/tree", handleProcessTree(db))
		analytics.GET("/resources/cpu", handleView(db, "SELECT * FROM v_resource_timeseries ORDER BY bucket"))
		analytics.GET("/resources/memory", handleView(db, "SELECT * FROM v_resource_timeseries ORDER BY bucket"))
		analytics.GET("/files/hot", handleHotFiles(db))
		analytics.GET("/network/connections", handleView(db, "SELECT * FROM v_network_analysis"))
		analytics.GET("/security/alerts", handleSecurityAlerts(db))
		analytics.GET("/security/sensitive-access", handleView(db, "SELECT * FROM v_exfiltration_risk"))
		analytics.GET("/sessions", handleSessions(db))
		analytics.GET("/timeline", handleTimeline(db))
	}
}

// queryRequest is the JSON body for POST /api/analytics/query.
type queryRequest struct {
	SQL    string `json:"sql" binding:"required"`
	Params []any  `json:"params"`
}

// handleQuery executes a read-only SQL query.
func handleQuery(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req queryRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logging.NamedZap("api").Warn("bad request", zap.Error(err), zap.String("path", c.Request.URL.Path))
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
			return
		}

		trimmed := strings.TrimSpace(req.SQL)
		upper := strings.ToUpper(trimmed)
		if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
			logging.NamedZap("api").Warn("sql not allowed", zap.String("path", c.Request.URL.Path))
			c.JSON(http.StatusForbidden, gin.H{"error": "only SELECT/WITH queries are allowed"})
			return
		}

		rows, err := db.Query(trimmed, req.Params...)
		if err != nil {
			respondInternalServerError(c, err)
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

// handleView executes a fixed SQL and returns the results.
func handleView(db *sql.DB, query string) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.Query("session_id")
		finalQuery := query
		var args []any
		if sessionID != "" {
			if strings.Contains(query, "WHERE") {
				finalQuery += " AND session_id = ?"
			} else {
				finalQuery += " WHERE session_id = ?"
			}
			args = append(args, sessionID)
		}

		rows, err := db.Query(finalQuery, args...)
		if err != nil {
			respondInternalServerError(c, err)
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

func handleToolCallLatency(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := `
			SELECT
				session_id,
				tool_name,
				PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY duration_ms) AS p50_ms,
				PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95_ms,
				PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) AS p99_ms,
				AVG(duration_ms) AS avg_ms,
				MIN(duration_ms) AS min_ms,
				MAX(duration_ms) AS max_ms,
				COUNT(*) AS sample_count
			FROM events_tool_call
			WHERE duration_ms IS NOT NULL
		`
		var args []any
		if sid := c.Query("session_id"); sid != "" {
			query += " AND session_id = ?"
			args = append(args, sid)
		}
		query += " GROUP BY session_id, tool_name ORDER BY p99_ms DESC"

		rows, err := db.Query(query, args...)
		if err != nil {
			respondInternalServerError(c, err)
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

func handleProcessTree(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := `
			SELECT
				pid, ppid, comm, filename, full_command,
				event_time, exit_code, duration_ms,
				event_type, session_id
			FROM events_process
			WHERE event_type IN ('EXEC', 'EXIT')
		`
		var args []any
		if sid := c.Query("session_id"); sid != "" {
			query += " AND session_id = ?"
			args = append(args, sid)
		}
		query += " ORDER BY event_time"

		rows, err := db.Query(query, args...)
		if err != nil {
			respondInternalServerError(c, err)
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

func handleHotFiles(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := "SELECT * FROM v_hot_files"
		var args []any
		if sid := c.Query("session_id"); sid != "" {
			query += " WHERE session_id = ?"
			args = append(args, sid)
		}
		limit := parseLimit(c.Query("limit"), 100)
		query += " LIMIT ?"
		args = append(args, limit)

		rows, err := db.Query(query, args...)
		if err != nil {
			respondInternalServerError(c, err)
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

func handleSecurityAlerts(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 单条告警：GET .../security/alerts?id=123
		if idStr := strings.TrimSpace(c.Query("id")); idStr != "" {
			idVal, err := strconv.ParseUint(idStr, 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
				return
			}
			rows, err := db.Query("SELECT * FROM v_security_alerts WHERE id = ?", idVal)
			if err != nil {
				respondInternalServerError(c, err)
				return
			}
			defer rows.Close()

			result := rowsToMaps(rows)
			if len(result) == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"data": result[0], "count": 1})
			return
		}

		query := "SELECT * FROM v_security_alerts"
		var args []any
		if sid := c.Query("session_id"); sid != "" {
			query += " WHERE session_id = ?"
			args = append(args, sid)
		}
		query += " ORDER BY event_time DESC"

		limit := parseLimit(c.Query("limit"), 1000)
		query += " LIMIT ?"
		args = append(args, limit)

		rows, err := db.Query(query, args...)
		if err != nil {
			respondInternalServerError(c, err)
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

func handleSessions(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := `
			SELECT
				session_id,
				start_time,
				end_time
			FROM sessions
			ORDER BY start_time DESC
		`
		rows, err := db.Query(query)
		if err != nil {
			respondInternalServerError(c, err)
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

func handleTimeline(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// UNION ALL across all event tables for a unified timeline.
		sessionFilter := ""
		var args []any
		if sid := c.Query("session_id"); sid != "" {
			sessionFilter = " WHERE session_id = ?"
			args = append(args, sid)
		}

		sourceFilter := c.Query("source")

		// Build per-table queries.
		type tableQuery struct {
			source string
			sql    string
		}
		tables := []tableQuery{
			{"process", `SELECT id, session_id, event_time, 'process' AS source, pid, comm,
				event_type, NULL AS tool_event_type, NULL AS tool_name, NULL AS tool_status,
				filepath, net_ip, net_port, full_command, data_json
				FROM events_process`},
			{"tool_call", `SELECT id, session_id, event_time, 'tool_call' AS source, pid, comm,
				NULL AS event_type, tool_event_type, tool_name, tool_status,
				tool_key_field AS filepath, NULL AS net_ip, NULL AS net_port, NULL AS full_command, data_json
				FROM events_tool_call`},
			{"system", `SELECT id, session_id, event_time, 'system' AS source, pid, comm,
				sys_type AS event_type, NULL AS tool_event_type, NULL AS tool_name, NULL AS tool_status,
				NULL AS filepath, NULL AS net_ip, NULL AS net_port, NULL AS full_command, data_json
				FROM events_system`},
			{"ssl", `SELECT id, session_id, event_time, 'ssl' AS source, pid, comm,
				NULL AS event_type, NULL AS tool_event_type, NULL AS tool_name, NULL AS tool_status,
				NULL AS filepath, NULL AS net_ip, NULL AS net_port, NULL AS full_command, data_json
				FROM events_ssl`},
			{"http_parser", `SELECT id, session_id, event_time, 'http_parser' AS source, pid, comm,
				NULL AS event_type, NULL AS tool_event_type, NULL AS tool_name, NULL AS tool_status,
				http_path AS filepath, NULL AS net_ip, NULL AS net_port, http_method AS full_command, data_json
				FROM events_http`},
			{"sse_processor", `SELECT id, session_id, event_time, 'sse_processor' AS source, pid, comm,
				NULL AS event_type, NULL AS tool_event_type, NULL AS tool_name, NULL AS tool_status,
				NULL AS filepath, NULL AS net_ip, NULL AS net_port, NULL AS full_command, data_json
				FROM events_sse`},
			{"security", `SELECT id, session_id, event_time, 'security' AS source, pid, comm,
				alert_type AS event_type, NULL AS tool_event_type, NULL AS tool_name, risk_level AS tool_status,
				description AS filepath, NULL AS net_ip, NULL AS net_port, NULL AS full_command, data_json
				FROM events_security`},
		}

		var parts []string
		var queryArgs []any
		for _, tq := range tables {
			if sourceFilter != "" && tq.source != sourceFilter {
				continue
			}
			q := tq.sql
			if sessionFilter != "" {
				q += sessionFilter
			}
			parts = append(parts, q)
			queryArgs = append(queryArgs, args...)
		}

		if len(parts) == 0 {
			c.JSON(http.StatusOK, gin.H{"data": []any{}, "count": 0})
			return
		}

		fullQuery := strings.Join(parts, " UNION ALL ") + " ORDER BY event_time DESC"

		limit := parseLimit(c.Query("limit"), 1000)
		fullQuery += " LIMIT ?"
		queryArgs = append(queryArgs, limit)

		rows, err := db.Query(fullQuery, queryArgs...)
		if err != nil {
			respondInternalServerError(c, err)
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

// parseLimit safely parses a limit query parameter with a default and max cap.
func parseLimit(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return defaultVal
	}
	if n > 10000 {
		return 10000
	}
	return n
}

// rowsToMaps converts sql.Rows to a slice of maps for JSON serialization.
func rowsToMaps(rows *sql.Rows) []map[string]interface{} {
	cols, err := rows.Columns()
	if err != nil {
		return nil
	}

	var result []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(cols))
		pointers := make([]interface{}, len(cols))
		for i := range values {
			pointers[i] = &values[i]
		}

		if err := rows.Scan(pointers...); err != nil {
			continue
		}

		row := make(map[string]interface{}, len(cols))
		for i, col := range cols {
			val := values[i]
			// Convert []byte to string for JSON friendliness.
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		result = append(result, row)
	}

	if result == nil {
		result = []map[string]interface{}{}
	}
	return result
}
