package httpserver

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
			return
		}

		trimmed := strings.TrimSpace(req.SQL)
		upper := strings.ToUpper(trimmed)
		if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
			c.JSON(http.StatusForbidden, gin.H{"error": "only SELECT/WITH queries are allowed"})
			return
		}

		rows, err := db.Query(trimmed, req.Params...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			FROM events
			WHERE source = 'tool_call'
			  AND tool_event_type = 'tool_call_end'
			  AND duration_ms IS NOT NULL
		`
		var args []any
		if sid := c.Query("session_id"); sid != "" {
			query += " AND session_id = ?"
			args = append(args, sid)
		}
		query += " GROUP BY session_id, tool_name ORDER BY p99_ms DESC"

		rows, err := db.Query(query, args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			FROM events
			WHERE source = 'process'
			  AND event_type IN ('EXEC', 'EXIT')
		`
		var args []any
		if sid := c.Query("session_id"); sid != "" {
			query += " AND session_id = ?"
			args = append(args, sid)
		}
		query += " ORDER BY event_time"

		rows, err := db.Query(query, args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		limit := c.DefaultQuery("limit", "100")
		query += " LIMIT " + limit

		rows, err := db.Query(query, args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

func handleSecurityAlerts(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := "SELECT * FROM v_security_alerts"
		var args []any
		if sid := c.Query("session_id"); sid != "" {
			query += " WHERE session_id = ?"
			args = append(args, sid)
		}
		query += " ORDER BY event_time DESC"

		if limit := c.Query("limit"); limit != "" {
			query += " LIMIT " + limit
		}

		rows, err := db.Query(query, args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
				COUNT(*) AS total_events,
				MIN(event_time) AS start_time,
				MAX(event_time) AS end_time,
				COUNT(DISTINCT source) AS source_types
			FROM events
			GROUP BY session_id
			ORDER BY start_time DESC
		`
		rows, err := db.Query(query)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
}

func handleTimeline(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := `
			SELECT
				id, session_id, event_time, source, pid, comm,
				event_type, tool_event_type, tool_name, tool_status,
				filepath, net_ip, net_port, full_command,
				is_sensitive_file, is_dangerous_cmd, data_json
			FROM events
		`
		var args []any
		conditions := []string{}
		if sid := c.Query("session_id"); sid != "" {
			conditions = append(conditions, "session_id = ?")
			args = append(args, sid)
		}
		if src := c.Query("source"); src != "" {
			conditions = append(conditions, "source = ?")
			args = append(args, src)
		}

		if len(conditions) > 0 {
			query += " WHERE " + strings.Join(conditions, " AND ")
		}
		query += " ORDER BY event_time DESC"

		limit := c.DefaultQuery("limit", "1000")
		query += " LIMIT " + limit

		rows, err := db.Query(query, args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		result := rowsToMaps(rows)
		c.JSON(http.StatusOK, gin.H{"data": result, "count": len(result)})
	}
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
