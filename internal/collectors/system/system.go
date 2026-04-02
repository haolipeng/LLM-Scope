package system

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

// Config controls /proc sampling.
type Config struct {
	IntervalSeconds int
	PID             int
	Comm            string
	IncludeChildren bool
	CPUThreshold    float64
	MemoryThreshold int
}

// Runner collects system metrics from /proc.
type Runner struct {
	config Config
}

func New(config Config) *Runner {
	if config.IntervalSeconds <= 0 {
		config.IntervalSeconds = 10
	}
	return &Runner{config: config}
}

func (s *Runner) ID() string {
	return "system"
}

func (s *Runner) Name() string {
	return "system"
}

func (s *Runner) Run(ctx context.Context) (<-chan *event.Event, error) {
	out := make(chan *event.Event, 100)
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

func (s *Runner) Stop() error {
	return nil
}

// processStats 保存单次 CPU 采样的用户态/内核态时间
type processStats struct {
	UTime     uint64
	STime     uint64
	Timestamp uint64
}

// getBootTimeNs 从 /proc/uptime 读取系统启动时间（纳秒）
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

// findTargetPIDs 根据配置的 PID 或进程名查找目标进程
func (s *Runner) findTargetPIDs() []uint32 {
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

// processExists 检查 /proc/<pid> 是否存在
func processExists(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// findPIDsByName 在 /proc 中按进程名模式匹配查找 PID
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

// getAllChildren 递归获取进程的所有子进程 PID
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

// collectProcessMetrics 采集目标进程组的 CPU/内存/线程指标
func collectProcessMetrics(pid uint32, allPids []uint32, timestamp uint64, previous map[uint32]processStats, cfg Config) (*event.Event, error) {
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

	return &event.Event{
		TimestampNs:     int64(timestamp),
		TimestampUnixMs: event.BootNsToUnixMs(int64(timestamp)),
		Source:          "system",
		PID:             pid,
		Comm:            processName,
		Data:            data,
	}, nil
}

// systemWideMetrics 采集系统级 load average 和内存指标
func systemWideMetrics(timestamp uint64) (*event.Event, error) {
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

	return &event.Event{
		TimestampNs:     int64(timestamp),
		TimestampUnixMs: event.BootNsToUnixMs(int64(timestamp)),
		Source:          "system",
		PID:             0,
		Comm:            "system",
		Data:            data,
	}, nil
}

// processMemory 从 /proc/<pid>/statm 读取 RSS 和 VSZ（KB）
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

// processCPUStats 从 /proc/<pid>/stat 读取用户态和内核态 CPU 时间
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

// calculateCPUPercent 通过前后两次采样差值计算 CPU 使用率
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

// threadCount 通过 /proc/<pid>/task 获取线程数
func threadCount(pid uint32) uint32 {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return 1
	}
	return uint32(len(entries))
}

// loadAverage 从 /proc/loadavg 读取 1/5/15 分钟负载
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

// systemMemory 从 /proc/meminfo 读取总量/空闲/可用内存（KB）
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

// parseMeminfo 解析 /proc/meminfo 中一行的数值
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

// cpuCores 通过 /sys/devices/system/cpu 获取 CPU 核心数
func cpuCores() int {
	entries, err := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*")
	if err != nil {
		return 0
	}
	return len(entries)
}
