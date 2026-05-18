package httpserver

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/haolipeng/LLM-Scope/internal/pipeline/sink"
)

func setupTestRouter(db *sql.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := r.Group("/api")
	registerAnalyticsRoutes(api, db)
	return r
}

func openAITrafficTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.duckdb")
	db, err := sink.OpenDuckDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDuckDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Insert session record.
	_, err = db.Exec(`INSERT INTO sessions (session_id, start_time) VALUES ('test-session', ?)`,
		time.Now())
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	return db
}

func insertHTTPEvent(t *testing.T, db *sql.DB, pid uint32, tid uint32, msgType, method, path string, statusCode uint16, eventTime time.Time, dataJSON string) {
	t.Helper()
	if dataJSON == "" {
		dataJSON = "{}"
	}
	_, err := db.Exec(`INSERT INTO events_http
		(session_id, timestamp_ns, event_time, pid, comm, http_message_type, http_method, http_path, http_status_code, http_tid, data_json)
		VALUES ('test-session', ?, ?, ?, 'curl', ?, ?, ?, ?, ?, ?)`,
		eventTime.UnixNano(), eventTime, pid, msgType, method, path, statusCode, tid, dataJSON)
	if err != nil {
		t.Fatalf("insert http event: %v", err)
	}
}

func insertSSEEvent(t *testing.T, db *sql.DB, pid uint32, connID string, eventTime time.Time, dataJSON string) {
	t.Helper()
	if dataJSON == "" {
		dataJSON = "{}"
	}
	_, err := db.Exec(`INSERT INTO events_sse
		(session_id, timestamp_ns, event_time, pid, comm, sse_connection_id, data_json)
		VALUES ('test-session', ?, ?, ?, 'curl', ?, ?)`,
		eventTime.UnixNano(), eventTime, pid, connID, dataJSON)
	if err != nil {
		t.Fatalf("insert sse event: %v", err)
	}
}

func TestAITraffic_InvalidPID(t *testing.T) {
	db := openAITrafficTestDB(t)
	router := setupTestRouter(db)

	req := httptest.NewRequest("GET", "/api/analytics/process/abc/ai-traffic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAITraffic_NormalPairing(t *testing.T) {
	db := openAITrafficTestDB(t)
	router := setupTestRouter(db)

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	reqData := `{"headers":{"host":"api.anthropic.com"},"body":{"model":"claude-3-opus"}}`

	// Insert a request and a response on the same tid.
	insertHTTPEvent(t, db, 1234, 100, "request", "POST", "/v1/messages", 0, base, reqData)
	insertHTTPEvent(t, db, 1234, 100, "response", "POST", "/v1/messages", 200, base.Add(500*time.Millisecond), `{"headers":{"host":"api.anthropic.com"}}`)

	req := httptest.NewRequest("GET", "/api/analytics/process/1234/ai-traffic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data  []json.RawMessage `json:"data"`
		Count int               `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("expected 1 pair, got %d", resp.Count)
	}

	// Verify the pair has both request and response.
	var pair struct {
		Index      int                    `json:"index"`
		Request    map[string]interface{} `json:"request"`
		Response   map[string]interface{} `json:"response"`
		DurationMs *int64                 `json:"duration_ms"`
	}
	if err := json.Unmarshal(resp.Data[0], &pair); err != nil {
		t.Fatalf("unmarshal pair: %v", err)
	}
	if pair.Request == nil {
		t.Error("expected request to be non-nil")
	}
	if pair.Response == nil {
		t.Error("expected response to be non-nil")
	}
	if pair.DurationMs == nil {
		t.Error("expected duration_ms to be non-nil")
	} else if *pair.DurationMs != 500 {
		t.Errorf("expected duration_ms=500, got %d", *pair.DurationMs)
	}
}

func TestAITraffic_SSEResponse(t *testing.T) {
	db := openAITrafficTestDB(t)
	router := setupTestRouter(db)

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	reqData := `{"headers":{"host":"api.openai.com"}}`

	// Insert a request.
	insertHTTPEvent(t, db, 1234, 200, "request", "POST", "/v1/chat/completions", 0, base, reqData)

	// Insert an SSE response for the same tid.
	insertSSEEvent(t, db, 1234, "1234:200:0", base.Add(time.Second), `{"type":"sse_response"}`)

	req := httptest.NewRequest("GET", "/api/analytics/process/1234/ai-traffic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Count int `json:"count"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Count != 1 {
		t.Errorf("expected 1 pair, got %d", resp.Count)
	}
}

func TestAITraffic_AIFilter(t *testing.T) {
	db := openAITrafficTestDB(t)
	router := setupTestRouter(db)

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// Insert AI request.
	insertHTTPEvent(t, db, 1234, 100, "request", "POST", "/v1/messages", 0, base,
		`{"headers":{"host":"api.anthropic.com"}}`)

	// Insert non-AI request.
	insertHTTPEvent(t, db, 1234, 101, "request", "GET", "/api/users", 0, base.Add(time.Second),
		`{"headers":{"host":"example.com"}}`)

	// Default: should only return 1 (AI only).
	req := httptest.NewRequest("GET", "/api/analytics/process/1234/ai-traffic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp struct {
		Count int `json:"count"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Count != 1 {
		t.Errorf("expected 1 AI pair, got %d", resp.Count)
	}

	// With all=true: should return 2.
	req2 := httptest.NewRequest("GET", "/api/analytics/process/1234/ai-traffic?all=true", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	json.Unmarshal(w2.Body.Bytes(), &resp)
	if resp.Count != 2 {
		t.Errorf("expected 2 pairs with all=true, got %d", resp.Count)
	}
}

func TestAITraffic_NoMatchingResponse(t *testing.T) {
	db := openAITrafficTestDB(t)
	router := setupTestRouter(db)

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// Insert only a request, no response.
	insertHTTPEvent(t, db, 1234, 100, "request", "POST", "/v1/messages", 0, base,
		`{"headers":{"host":"api.anthropic.com"}}`)

	req := httptest.NewRequest("GET", "/api/analytics/process/1234/ai-traffic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var pair struct {
		Index      int                    `json:"index"`
		Request    map[string]interface{} `json:"request"`
		Response   map[string]interface{} `json:"response"`
		DurationMs *int64                 `json:"duration_ms"`
	}
	var resp struct {
		Data  []json.RawMessage `json:"data"`
		Count int               `json:"count"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Count != 1 {
		t.Fatalf("expected 1 pair, got %d", resp.Count)
	}
	json.Unmarshal(resp.Data[0], &pair)
	if pair.Response != nil {
		t.Error("expected response to be nil")
	}
	if pair.DurationMs != nil {
		t.Error("expected duration_ms to be nil")
	}
}

func TestAITraffic_MultipleTIDs(t *testing.T) {
	db := openAITrafficTestDB(t)
	router := setupTestRouter(db)

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// TID 100: request + response
	insertHTTPEvent(t, db, 1234, 100, "request", "POST", "/v1/messages", 0, base,
		`{"headers":{"host":"api.anthropic.com"}}`)
	insertHTTPEvent(t, db, 1234, 100, "response", "POST", "/v1/messages", 200, base.Add(200*time.Millisecond),
		`{"headers":{"host":"api.anthropic.com"}}`)

	// TID 101: request + response
	insertHTTPEvent(t, db, 1234, 101, "request", "POST", "/v1/chat/completions", 0, base.Add(time.Second),
		`{"headers":{"host":"api.openai.com"}}`)
	insertHTTPEvent(t, db, 1234, 101, "response", "POST", "/v1/chat/completions", 200, base.Add(1500*time.Millisecond),
		`{"headers":{"host":"api.openai.com"}}`)

	req := httptest.NewRequest("GET", "/api/analytics/process/1234/ai-traffic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp struct {
		Count int `json:"count"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Count != 2 {
		t.Errorf("expected 2 pairs from different TIDs, got %d", resp.Count)
	}
}

func TestAITraffic_EmptyResult(t *testing.T) {
	db := openAITrafficTestDB(t)
	router := setupTestRouter(db)

	req := httptest.NewRequest("GET", "/api/analytics/process/9999/ai-traffic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Data  []interface{} `json:"data"`
		Count int           `json:"count"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Count != 0 {
		t.Errorf("expected 0 pairs, got %d", resp.Count)
	}
	if len(resp.Data) != 0 {
		t.Errorf("expected empty data array, got %d items", len(resp.Data))
	}
}
