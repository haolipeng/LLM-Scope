package event

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	bootTimeOnce sync.Once
	bootTime     time.Time
)

// BootTime returns the system boot time, cached after the first lookup.
func BootTime() time.Time {
	bootTimeOnce.Do(func() {
		if t, ok := bootTimeFromProcStat(); ok {
			bootTime = t
			return
		}
		if t, ok := bootTimeFromUptime(); ok {
			bootTime = t
			return
		}
		bootTime = time.Now()
	})

	return bootTime
}

// BootNsToTime converts nanoseconds since boot into a time.Time using cached boot time.
func BootNsToTime(nsSinceBoot int64) time.Time {
	return BootTime().Add(time.Duration(nsSinceBoot))
}

// BootNsToUnixMs converts nanoseconds since boot into milliseconds since UNIX epoch.
func BootNsToUnixMs(nsSinceBoot int64) int64 {
	return BootNsToTime(nsSinceBoot).UnixMilli()
}

func bootTimeFromProcStat() (time.Time, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				break
			}
			secs, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				break
			}
			return time.Unix(secs, 0), true
		}
	}

	return time.Time{}, false
}

func bootTimeFromUptime() (time.Time, bool) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, false
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return time.Time{}, false
	}
	uptimeSecs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}, false
	}

	return time.Now().Add(-time.Duration(uptimeSecs * float64(time.Second))), true
}
