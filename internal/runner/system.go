package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/eunomia-bpf/agentsight/internal/core"
)

// SystemConfig controls /proc sampling.
type SystemConfig struct {
	IntervalSeconds int
	PID             int
	Comm            string
	IncludeChildren bool
	CPUThreshold    float64
	MemoryThreshold int
}

// SystemRunner collects system metrics from /proc.
type SystemRunner struct {
	config SystemConfig
}

func NewSystemRunner(config SystemConfig) *SystemRunner {
	if config.IntervalSeconds <= 0 {
		config.IntervalSeconds = 2
	}
	return &SystemRunner{config: config}
}

func (s *SystemRunner) Name() string {
	return "system"
}

func (s *SystemRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
	out := make(chan *core.Event, 100)
	go func() {
		defer close(out)
		interval := time.NewTicker(time.Duration(s.config.IntervalSeconds) * time.Second)
		defer interval.Stop()

		previous := map[uint32]processStats{}
		for {
			select {
			case <-ctx.Done():
				return
			case <-interval.C:
				timestamp := getBootTimeNs()

				targets := s.findTargetPIDs()
				if len(targets) == 0 {
					if s.config.PID != 0 || s.config.Comm != "" {
						continue
					}
					event, err := systemWideMetrics(timestamp)
					if err == nil {
						out <- event
					}
					continue
				}

				for _, pid := range targets {
					pids := []uint32{pid}
					if s.config.IncludeChildren {
						pids = append(pids, getAllChildren(pid)...)
					}
					event, err := collectProcessMetrics(pid, pids, timestamp, previous, s.config)
					if err != nil {
						continue
					}
					out <- event
				}
			}
		}
	}()

	return out, nil
}

func (s *SystemRunner) Stop() error {
	return nil
}

type processStats struct {
	UTime     uint64
	STime     uint64
	Timestamp uint64
}

func getBootTimeNs() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return uint64(secs * 1_000_000_000.0)
}

func (s *SystemRunner) findTargetPIDs() []uint32 {
	if s.config.PID != 0 {
		if processExists(uint32(s.config.PID)) {
			return []uint32{uint32(s.config.PID)}
		}
		return nil
	}
	if s.config.Comm != "" {
		return findPIDsByName(s.config.Comm)
	}
	return nil
}

func processExists(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func findPIDsByName(pattern string) []uint32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []uint32
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		if strings.Contains(strings.TrimSpace(string(comm)), pattern) {
			pids = append(pids, uint32(pid))
		}
	}
	return pids
}

func getAllChildren(parent uint32) []uint32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var children []uint32
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		fields := strings.Fields(string(stat))
		if len(fields) < 4 {
			continue
		}
		ppid, err := strconv.ParseUint(fields[3], 10, 32)
		if err != nil {
			continue
		}
		if uint32(ppid) == parent {
			child := uint32(pid)
			children = append(children, child)
			children = append(children, getAllChildren(child)...)
		}
	}
	return children
}

func collectProcessMetrics(pid uint32, allPids []uint32, timestamp uint64, previous map[uint32]processStats, cfg SystemConfig) (*core.Event, error) {
	var totalRSS uint64
	var totalVSZ uint64
	var totalCPU float64
	var threads uint32
	processName := "unknown"

	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		processName = strings.TrimSpace(string(comm))
	}

	for _, current := range allPids {
		if !processExists(current) {
			continue
		}
		if rss, vsz, err := processMemory(current); err == nil {
			totalRSS += rss
			totalVSZ += vsz
		}
		if stats, err := processCPUStats(current); err == nil {
			cpuPercent := calculateCPUPercent(current, stats, previous, timestamp)
			totalCPU += cpuPercent
		}
		if current == pid {
			threads = threadCount(current)
		}
	}

	childrenCount := len(allPids)
	if childrenCount > 0 {
		childrenCount -= 1
	}

	alert := false
	if cfg.CPUThreshold > 0 && totalCPU >= cfg.CPUThreshold {
		alert = true
	}
	if cfg.MemoryThreshold > 0 && int(totalRSS/1024) >= cfg.MemoryThreshold {
		alert = true
	}

	payload := map[string]interface{}{
		"type":      "system_metrics",
		"pid":       pid,
		"comm":      processName,
		"timestamp": timestamp,
		"cpu": map[string]interface{}{
			"percent": fmt.Sprintf("%.2f", totalCPU),
			"cores":   cpuCores(),
		},
		"memory": map[string]interface{}{
			"rss_kb": totalRSS,
			"rss_mb": totalRSS / 1024,
			"vsz_kb": totalVSZ,
			"vsz_mb": totalVSZ / 1024,
		},
		"process": map[string]interface{}{
			"threads":  threads,
			"children": childrenCount,
		},
		"alert": alert,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &core.Event{
		TimestampNs:     int64(timestamp),
		TimestampUnixMs: core.BootNsToUnixMs(int64(timestamp)),
		Source:          "system",
		PID:             pid,
		Comm:            processName,
		Data:            data,
	}, nil
}

func systemWideMetrics(timestamp uint64) (*core.Event, error) {
	load1, load5, load15 := loadAverage()
	totalKB, freeKB, availKB := systemMemory()
	usedKB := totalKB - availKB
	usedPct := 0.0
	if totalKB > 0 {
		usedPct = (float64(usedKB) / float64(totalKB)) * 100
	}

	payload := map[string]interface{}{
		"type":      "system_wide",
		"timestamp": timestamp,
		"cpu": map[string]interface{}{
			"cores":          cpuCores(),
			"load_avg_1min":  load1,
			"load_avg_5min":  load5,
			"load_avg_15min": load15,
		},
		"memory": map[string]interface{}{
			"total_kb":     totalKB,
			"total_mb":     totalKB / 1024,
			"used_kb":      usedKB,
			"used_mb":      usedKB / 1024,
			"free_kb":      freeKB,
			"available_kb": availKB,
			"used_percent": fmt.Sprintf("%.2f", usedPct),
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &core.Event{
		TimestampNs:     int64(timestamp),
		TimestampUnixMs: core.BootNsToUnixMs(int64(timestamp)),
		Source:          "system",
		PID:             0,
		Comm:            "system",
		Data:            data,
	}, nil
}

func processMemory(pid uint32) (uint64, uint64, error) {
	statm, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(string(statm))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("invalid statm")
	}
	vszPages, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	rssPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}

	pageSize := uint64(4)
	return rssPages * pageSize, vszPages * pageSize, nil
}

func processCPUStats(pid uint32) (processStats, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return processStats{}, err
	}
	fields := strings.Fields(string(stat))
	if len(fields) < 15 {
		return processStats{}, fmt.Errorf("invalid stat")
	}
	utime, err := strconv.ParseUint(fields[13], 10, 64)
	if err != nil {
		return processStats{}, err
	}
	stime, err := strconv.ParseUint(fields[14], 10, 64)
	if err != nil {
		return processStats{}, err
	}
	return processStats{UTime: utime, STime: stime, Timestamp: getBootTimeNs()}, nil
}

func calculateCPUPercent(pid uint32, current processStats, previous map[uint32]processStats, timestamp uint64) float64 {
	prev, ok := previous[pid]
	previous[pid] = current
	if !ok {
		return 0
	}

	timeDelta := float64(timestamp-prev.Timestamp) / 1_000_000_000.0
	if timeDelta <= 0 {
		return 0
	}
	cpuDelta := (current.UTime + current.STime) - (prev.UTime + prev.STime)
	userHZ := 100.0
	return (float64(cpuDelta) / userHZ / timeDelta) * 100
}

func threadCount(pid uint32) uint32 {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return 1
	}
	return uint32(len(entries))
}

func loadAverage() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	v1, _ := strconv.ParseFloat(fields[0], 64)
	v5, _ := strconv.ParseFloat(fields[1], 64)
	v15, _ := strconv.ParseFloat(fields[2], 64)
	return v1, v5, v15
}

func systemMemory() (uint64, uint64, uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}
	var total, free, avail uint64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			total = parseMeminfo(line)
		} else if strings.HasPrefix(line, "MemFree:") {
			free = parseMeminfo(line)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			avail = parseMeminfo(line)
		}
	}
	return total, free, avail
}

func parseMeminfo(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	value, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func cpuCores() int {
	entries, err := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*")
	if err != nil {
		return 0
	}
	return len(entries)
}
