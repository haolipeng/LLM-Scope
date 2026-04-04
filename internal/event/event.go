package event

import (
	"encoding/json"
	"sync/atomic"
	"time"
)

var streamSeqGen atomic.Uint64

// NextStreamSeq returns a monotonically increasing sequence used to correlate an
// event with downstream rows (e.g. security alerts referencing the triggering row id).
func NextStreamSeq() uint64 {
	return streamSeqGen.Add(1)
}

// Event is the unified event shape used across runners and analyzers.
type Event struct {
	StreamSeq       uint64          `json:"stream_seq,omitempty"`
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
