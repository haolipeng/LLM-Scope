package event

import (
	"encoding/json"
	"time"
)

// Event is the unified event shape used across runners and analyzers.
type Event struct {
	TimestampNs     int64           `json:"timestamp_ns"`
	TimestampUnixMs int64           `json:"timestamp_unix_ms,omitempty"`
	Source          string          `json:"source"` // "ssl", "process", "system"
	PID             uint32          `json:"pid"`
	Comm            string          `json:"comm"`
	Data            json.RawMessage `json:"data"`
}

func (e *Event) Time() time.Time {
	return BootNsToTime(e.TimestampNs)
}
