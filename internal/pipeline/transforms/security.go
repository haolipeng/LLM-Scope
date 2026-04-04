package transforms

import (
	"context"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

// SecurityRule checks an event and optionally returns a SecurityAlert.
type SecurityRule interface {
	Name() string
	Check(event *event.Event, data map[string]interface{}) *SecurityAlert
}

// SecurityAlert describes a security finding.
type SecurityAlert struct {
	AlertType   string     `json:"alert_type"`
	RiskLevel   string     `json:"risk_level"` // low, medium, high, critical
	Description string     `json:"description"`
	Evidence    []Evidence `json:"evidence"`
}

// Evidence references the original event that triggered the alert.
type Evidence struct {
	SourceTable string `json:"source_table"`
	EventType   string `json:"event_type,omitempty"`
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm,omitempty"`
	TimestampNs int64  `json:"timestamp_ns"`
	Detail      string `json:"detail,omitempty"`
}

// SecurityAnalyzer is a pipeline Analyzer that checks every event against a set
// of SecurityRules. Original events pass through unmodified; for each rule hit a
// separate security alert event is injected into the output stream.
type SecurityAnalyzer struct {
	rules []SecurityRule
}

// NewSecurityAnalyzer creates a SecurityAnalyzer with the built-in rule set.
func NewSecurityAnalyzer() *SecurityAnalyzer {
	return &SecurityAnalyzer{
		rules: []SecurityRule{
			&SensitiveFileRule{},
			&DangerousCommandRule{},
			&CredentialChangeRule{},
			&SuspiciousNetworkRule{},
		},
	}
}

// NewSecurityAnalyzerWithRules creates a SecurityAnalyzer with custom rules.
func NewSecurityAnalyzerWithRules(rules []SecurityRule) *SecurityAnalyzer {
	return &SecurityAnalyzer{rules: rules}
}

func (s *SecurityAnalyzer) Name() string { return "security_analyzer" }

// Process passes every event through, and injects extra security alert events
// for each rule that fires.
func (s *SecurityAnalyzer) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	out := make(chan *event.Event, 100)

	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-in:
				if !ok {
					return
				}
				// Assign stream sequence before forwarding so security alerts can reference this row id after DuckDB insert.
				if ev.StreamSeq == 0 {
					ev.StreamSeq = event.NextStreamSeq()
				}
				// Always forward the original event.
				out <- ev

				// Skip events that are already security alerts.
				if ev.Source == "security" {
					continue
				}

				// Parse data once for all rules.
				var data map[string]interface{}
				if err := json.Unmarshal(ev.Data, &data); err != nil {
					continue
				}

				// Check each rule.
				for _, rule := range s.rules {
					if alert := rule.Check(ev, data); alert != nil {
						out <- buildSecurityEvent(ev, alert)
					}
				}
			}
		}
	}()

	return out
}

// buildSecurityEvent creates a new Event with source="security" from an alert.
func buildSecurityEvent(original *event.Event, alert *SecurityAlert) *event.Event {
	// Build the evidence if not already provided.
	if len(alert.Evidence) == 0 {
		alert.Evidence = []Evidence{{
			SourceTable: sourceToTable(original.Source),
			PID:         original.PID,
			Comm:        original.Comm,
			TimestampNs: original.TimestampNs,
		}}
	}

	evidenceJSON, _ := json.Marshal(alert.Evidence)

	payload := map[string]interface{}{
		"alert_type":         alert.AlertType,
		"risk_level":         alert.RiskLevel,
		"description":        alert.Description,
		"source_table":       sourceToTable(original.Source),
		"source_stream_seq":  strconv.FormatUint(original.StreamSeq, 10),
		"evidence":           json.RawMessage(evidenceJSON),
	}
	data, _ := json.Marshal(payload)

	now := time.Now()
	return &event.Event{
		TimestampNs:     original.TimestampNs,
		TimestampUnixMs: now.UnixMilli(),
		Source:          "security",
		PID:             original.PID,
		Comm:            original.Comm,
		Data:            data,
	}
}

func sourceToTable(source string) string {
	switch source {
	case "process":
		return "events_process"
	case "tool_call":
		return "events_tool_call"
	case "system":
		return "events_system"
	case "ssl":
		return "events_ssl"
	case "http_parser":
		return "events_http"
	case "sse_processor":
		return "events_sse"
	default:
		return "events_" + source
	}
}

// ============================================================
// Built-in rules
// ============================================================

// --- SensitiveFileRule ---

var sensitivePathPatterns = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	".env",
	".ssh/",
	"id_rsa",
	"id_ed25519",
	"credentials",
	"secret",
	".aws/",
	".kube/config",
	"/proc/self/",
}

type SensitiveFileRule struct{}

func (r *SensitiveFileRule) Name() string { return "sensitive_file_access" }

func (r *SensitiveFileRule) Check(event *event.Event, data map[string]interface{}) *SecurityAlert {
	if event.Source != "process" {
		return nil
	}

	et, _ := data["event"].(string)
	if et != "FILE_OPEN" && et != "FILE_DELETE" && et != "FILE_RENAME" {
		return nil
	}

	// Check filepath and filepath2 (for rename).
	paths := []string{}
	if fp, ok := data["filepath"].(string); ok && fp != "" {
		paths = append(paths, fp)
	}
	if op, ok := data["oldpath"].(string); ok && op != "" {
		paths = append(paths, op)
	}
	if np, ok := data["newpath"].(string); ok && np != "" {
		paths = append(paths, np)
	}

	for _, path := range paths {
		if isSensitivePath(path) {
			return &SecurityAlert{
				AlertType:   "sensitive_file_access",
				RiskLevel:   "high",
				Description: event.Comm + " accessed sensitive file: " + path,
				Evidence: []Evidence{{
					SourceTable: "events_process",
					EventType:   et,
					PID:         event.PID,
					Comm:        event.Comm,
					TimestampNs: event.TimestampNs,
					Detail:      path,
				}},
			}
		}
	}
	return nil
}

func isSensitivePath(path string) bool {
	lower := strings.ToLower(path)
	for _, pattern := range sensitivePathPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// --- DangerousCommandRule ---

var dangerousCmdPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\brm\s+(-[^\s]*)?-r`),
	regexp.MustCompile(`\bchmod\s+777\b`),
	regexp.MustCompile(`\bcurl\b.*\|\s*\bbash\b`),
	regexp.MustCompile(`\bwget\b.*\|\s*\bbash\b`),
	regexp.MustCompile(`\bmkfifo\b`),
	regexp.MustCompile(`\bnc\s+-[^\s]*l`),
	regexp.MustCompile(`/dev/tcp/`),
	regexp.MustCompile(`\bdd\s+.*of=/dev/`),
	regexp.MustCompile(`>\s*/etc/`),
}

type DangerousCommandRule struct{}

func (r *DangerousCommandRule) Name() string { return "dangerous_command" }

func (r *DangerousCommandRule) Check(event *event.Event, data map[string]interface{}) *SecurityAlert {
	if event.Source != "process" {
		return nil
	}
	et, _ := data["event"].(string)
	if et != "EXEC" {
		return nil
	}

	cmd, _ := data["full_command"].(string)
	if cmd == "" {
		return nil
	}

	if isDangerousCommand(cmd) {
		return &SecurityAlert{
			AlertType:   "dangerous_command",
			RiskLevel:   "critical",
			Description: event.Comm + " executed dangerous command: " + cmd,
			Evidence: []Evidence{{
				SourceTable: "events_process",
				EventType:   "EXEC",
				PID:         event.PID,
				Comm:        event.Comm,
				TimestampNs: event.TimestampNs,
				Detail:      cmd,
			}},
		}
	}
	return nil
}

func isDangerousCommand(cmd string) bool {
	for _, re := range dangerousCmdPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// --- CredentialChangeRule ---

type CredentialChangeRule struct{}

func (r *CredentialChangeRule) Name() string { return "credential_change" }

func (r *CredentialChangeRule) Check(event *event.Event, data map[string]interface{}) *SecurityAlert {
	if event.Source != "process" {
		return nil
	}
	et, _ := data["event"].(string)
	if et != "CRED_CHANGE" {
		return nil
	}

	return &SecurityAlert{
		AlertType:   "credential_change",
		RiskLevel:   "high",
		Description: event.Comm + " triggered credential change",
		Evidence: []Evidence{{
			SourceTable: "events_process",
			EventType:   "CRED_CHANGE",
			PID:         event.PID,
			Comm:        event.Comm,
			TimestampNs: event.TimestampNs,
		}},
	}
}

// --- SuspiciousNetworkRule ---

// commonPorts that are generally safe (web, DNS, SSH, dev servers, proxies).
var commonPorts = map[uint32]bool{
	22: true, 53: true, 80: true, 443: true,
	3000: true, 3001: true, 3306: true, 5000: true, 5432: true,
	5173: true, 5174: true, 6379: true, 8000: true, 8080: true,
	8443: true, 8888: true, 9090: true, 9200: true, 9300: true,
	// Common proxy ports (Clash, V2Ray, Shadowsocks, etc.)
	1080: true, 7890: true, 7891: true, 7892: true, 7893: true,
	7897: true, 10808: true, 10809: true,
}

var privateNetworks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7",
	} {
		_, n, _ := net.ParseCIDR(cidr)
		privateNetworks = append(privateNetworks, n)
	}
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	for _, n := range privateNetworks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type SuspiciousNetworkRule struct{}

func (r *SuspiciousNetworkRule) Name() string { return "suspicious_network" }

func (r *SuspiciousNetworkRule) Check(event *event.Event, data map[string]interface{}) *SecurityAlert {
	if event.Source != "process" {
		return nil
	}
	et, _ := data["event"].(string)
	if et != "NET_CONNECT" {
		return nil
	}

	port := uint32(0)
	if p, ok := data["port"].(float64); ok {
		port = uint32(p)
	}

	if port == 0 || commonPorts[port] {
		return nil
	}

	ip, _ := data["ip"].(string)

	if isPrivateIP(ip) {
		return nil
	}

	return &SecurityAlert{
		AlertType:   "suspicious_network",
		RiskLevel:   "medium",
		Description: event.Comm + " connected to unusual port " + ip + ":" + portStr(port),
		Evidence: []Evidence{{
			SourceTable: "events_process",
			EventType:   "NET_CONNECT",
			PID:         event.PID,
			Comm:        event.Comm,
			TimestampNs: event.TimestampNs,
			Detail:      ip + ":" + portStr(port),
		}},
	}
}

func portStr(port uint32) string {
	return strconv.FormatUint(uint64(port), 10)
}
