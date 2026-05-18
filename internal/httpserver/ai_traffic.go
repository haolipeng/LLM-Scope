package httpserver

import (
	"database/sql"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/haolipeng/LLM-Scope/internal/logging"
	"go.uber.org/zap"
)

// Known AI API hosts for filtering.
var aiHosts = []string{
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
	"api.deepseek.com",
	"api.mistral.ai",
	"api.cohere.com",
	"api.together.xyz",
	"openrouter.ai",
}

// Known AI API path prefixes for filtering.
var aiPathPrefixes = []string{
	"/v1/messages",
	"/v1/chat/completions",
	"/v1/responses",
	"/v1/completions",
	"/api/generate",
	"/api/chat",
}

// aiTrafficPair represents a matched request-response pair.
type aiTrafficPair struct {
	Index      int                    `json:"index"`
	Request    map[string]interface{} `json:"request"`
	Response   map[string]interface{} `json:"response"`
	DurationMs *int64                 `json:"duration_ms"`
}

func handleAITraffic(db *sql.DB) gin.HandlerFunc {
	log := logging.NamedZap("ai-traffic")
	return func(c *gin.Context) {
		pidStr := c.Param("pid")
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			log.Warn("invalid pid param", zap.String("pid", pidStr))
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pid"})
			return
		}

		sessionID := c.Query("session_id")
		showAll := c.Query("all") == "true"
		log.Info("ai-traffic request",
			zap.Uint64("pid", pid),
			zap.String("session_id", sessionID),
			zap.Bool("show_all", showAll),
		)

		// Build HTTP events query.
		httpQuery := `SELECT * FROM events_http WHERE pid = ?`
		var httpArgs []interface{}
		httpArgs = append(httpArgs, pid)

		if sessionID != "" {
			httpQuery += " AND session_id = ?"
			httpArgs = append(httpArgs, sessionID)
		}

		if !showAll {
			httpQuery += ` AND (
				json_extract_string(data_json, '$.headers.host') IN (` + buildPlaceholders(len(aiHosts)) + `)
				OR ` + buildPathConditions(len(aiPathPrefixes)) + `
			)`
			for _, h := range aiHosts {
				httpArgs = append(httpArgs, h)
			}
			for _, p := range aiPathPrefixes {
				httpArgs = append(httpArgs, p+"%")
			}
		}

		httpQuery += " ORDER BY event_time ASC"

		log.Debug("http query", zap.String("sql", httpQuery), zap.Any("args", httpArgs))

		httpRows, err := db.Query(httpQuery, httpArgs...)
		if err != nil {
			log.Error("http query failed", zap.Error(err))
			respondInternalServerError(c, err)
			return
		}
		defer httpRows.Close()
		httpEvents := rowsToMaps(httpRows)
		log.Info("http events loaded", zap.Int("count", len(httpEvents)))

		// Build SSE events query.
		sseQuery := `SELECT * FROM events_sse WHERE pid = ?`
		var sseArgs []interface{}
		sseArgs = append(sseArgs, pid)

		if sessionID != "" {
			sseQuery += " AND session_id = ?"
			sseArgs = append(sseArgs, sessionID)
		}

		sseQuery += " ORDER BY event_time ASC"

		sseRows, err := db.Query(sseQuery, sseArgs...)
		if err != nil {
			log.Error("sse query failed", zap.Error(err))
			respondInternalServerError(c, err)
			return
		}
		defer sseRows.Close()
		sseEvents := rowsToMaps(sseRows)
		log.Info("sse events loaded", zap.Int("count", len(sseEvents)))

		// Pair requests with responses.
		pairs := pairAITraffic(httpEvents, sseEvents)
		log.Info("ai-traffic response",
			zap.Uint64("pid", pid),
			zap.Int("http_events", len(httpEvents)),
			zap.Int("sse_events", len(sseEvents)),
			zap.Int("pairs", len(pairs)),
		)

		c.JSON(http.StatusOK, gin.H{"data": pairs, "count": len(pairs)})
	}
}

// pairAITraffic matches HTTP requests with their responses (HTTP or SSE).
func pairAITraffic(httpEvents, sseEvents []map[string]interface{}) []aiTrafficPair {
	// Group HTTP events by tid.
	httpByTID := make(map[uint32][]map[string]interface{})
	for _, ev := range httpEvents {
		tid := extractUint32(ev["http_tid"])
		httpByTID[tid] = append(httpByTID[tid], ev)
	}

	// Group SSE events by tid (extracted from sse_connection_id format "pid:tid:window").
	sseByTID := make(map[uint32][]map[string]interface{})
	for _, ev := range sseEvents {
		connID, _ := ev["sse_connection_id"].(string)
		tid := parseTIDFromConnectionID(connID)
		sseByTID[tid] = append(sseByTID[tid], ev)
	}

	var pairs []aiTrafficPair
	index := 1

	// Process each tid group.
	allTIDs := make(map[uint32]bool)
	for tid := range httpByTID {
		allTIDs[tid] = true
	}

	// Sort TIDs for deterministic output.
	var sortedTIDs []uint32
	for tid := range allTIDs {
		sortedTIDs = append(sortedTIDs, tid)
	}
	sort.Slice(sortedTIDs, func(i, j int) bool { return sortedTIDs[i] < sortedTIDs[j] })

	for _, tid := range sortedTIDs {
		events := httpByTID[tid]
		sseEventsForTID := sseByTID[tid]

		// Sort events by time within the tid group.
		sort.Slice(events, func(i, j int) bool {
			return getEventTime(events[i]).Before(getEventTime(events[j]))
		})
		sort.Slice(sseEventsForTID, func(i, j int) bool {
			return getEventTime(sseEventsForTID[i]).Before(getEventTime(sseEventsForTID[j]))
		})

		sseIdx := 0
		for i, ev := range events {
			msgType, _ := ev["http_message_type"].(string)
			if msgType != "request" {
				continue
			}

			reqTime := getEventTime(ev)
			var response map[string]interface{}
			var durationMs *int64

			// Look for HTTP response in subsequent events of the same tid.
			for j := i + 1; j < len(events); j++ {
				nextMsgType, _ := events[j]["http_message_type"].(string)
				if nextMsgType == "response" {
					response = events[j]
					respTime := getEventTime(events[j])
					d := respTime.Sub(reqTime).Milliseconds()
					durationMs = &d
					break
				}
				// If we hit another request, stop looking.
				if nextMsgType == "request" {
					break
				}
			}

			// If no HTTP response found, look for SSE response after the request time.
			if response == nil && sseIdx < len(sseEventsForTID) {
				for sseIdx < len(sseEventsForTID) {
					sseTime := getEventTime(sseEventsForTID[sseIdx])
					if sseTime.After(reqTime) || sseTime.Equal(reqTime) {
						response = sseEventsForTID[sseIdx]
						d := sseTime.Sub(reqTime).Milliseconds()
						durationMs = &d
						sseIdx++
						break
					}
					sseIdx++
				}
			}

			pairs = append(pairs, aiTrafficPair{
				Index:      index,
				Request:    ev,
				Response:   response,
				DurationMs: durationMs,
			})
			index++
		}
	}

	// Sort final pairs by request time.
	sort.Slice(pairs, func(i, j int) bool {
		return getEventTime(pairs[i].Request).Before(getEventTime(pairs[j].Request))
	})
	// Re-index after sorting.
	for i := range pairs {
		pairs[i].Index = i + 1
	}

	if pairs == nil {
		pairs = []aiTrafficPair{}
	}
	return pairs
}

// getEventTime extracts the event_time from a row map.
func getEventTime(row map[string]interface{}) time.Time {
	if row == nil {
		return time.Time{}
	}
	switch v := row["event_time"].(type) {
	case time.Time:
		return v
	case string:
		t, _ := time.Parse(time.RFC3339Nano, v)
		if t.IsZero() {
			t, _ = time.Parse("2006-01-02 15:04:05.999999", v)
		}
		if t.IsZero() {
			t, _ = time.Parse("2006-01-02T15:04:05.999999Z", v)
		}
		return t
	}
	return time.Time{}
}

// extractUint32 converts an interface value to uint32.
func extractUint32(v interface{}) uint32 {
	switch n := v.(type) {
	case int64:
		return uint32(n)
	case uint32:
		return n
	case uint64:
		return uint32(n)
	case float64:
		return uint32(n)
	case int32:
		return uint32(n)
	case int:
		return uint32(n)
	}
	return 0
}

// parseTIDFromConnectionID extracts tid from connection ID format "pid:tid:window".
func parseTIDFromConnectionID(connID string) uint32 {
	parts := strings.Split(connID, ":")
	if len(parts) < 2 {
		return 0
	}
	tid, _ := strconv.ParseUint(parts[1], 10, 32)
	return uint32(tid)
}

// buildPlaceholders returns "?, ?, ?" for n placeholders.
func buildPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	p := make([]string, n)
	for i := range p {
		p[i] = "?"
	}
	return strings.Join(p, ", ")
}

// buildPathConditions returns "http_path LIKE ? OR http_path LIKE ? ..." for n paths.
func buildPathConditions(n int) string {
	if n <= 0 {
		return "FALSE"
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "http_path LIKE ?"
	}
	return strings.Join(parts, " OR ")
}
