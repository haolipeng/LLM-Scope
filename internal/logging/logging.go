// 实现见 doc.go 中的包说明；本文件为 Init 与全局 logger 访问器。
package logging

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	mu           sync.RWMutex
	sugar        *zap.SugaredLogger
	underlying   *zap.Logger
	defaultSugar *zap.SugaredLogger
)

func init() {
	// 在 Init 之前：仅输出到 stderr，避免完全静默（例如单测直接调用 collector）。
	cfg := zap.NewProductionConfig()
	cfg.Encoding = "console"
	cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	if l, err := cfg.Build(); err == nil {
		defaultSugar = l.Sugar()
		underlying = l
	} else {
		nop := zap.NewNop()
		defaultSugar = nop.Sugar()
		underlying = nop
	}
	sugar = defaultSugar
}

// Config 应用日志初始化参数。
type Config struct {
	// AppLogPath 非空时作为 zap 主输出文件；为空则根据 EventLogPath 推导。
	AppLogPath string
	// EventLogPath 与 --log-file 一致（事件 JSONL）；用于推导应用日志文件名，避免与事件文件相同。
	EventLogPath string
	Rotate       bool
	MaxSizeMB    int
	// Quiet 为 true 时仅写文件，不镜像到 stderr。
	Quiet bool
}

// deriveAppLogPath 将事件日志路径映射为应用日志路径，例如 record.log -> record.app.log。
func deriveAppLogPath(eventLogPath string) string {
	if eventLogPath == "" {
		return "agentsight.app.log"
	}
	dir := filepath.Dir(eventLogPath)
	base := filepath.Base(eventLogPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if ext == "" {
		return filepath.Join(dir, base+".app.log")
	}
	return filepath.Join(dir, stem+".app"+ext)
}

// Init 初始化全局 zap：主输出为文件（JSON 行），可选镜像到 stderr。
// 可多次调用，后一次覆盖前一次（例如测试）。
func Init(cfg Config) error {
	path := cfg.AppLogPath
	if path == "" {
		path = deriveAppLogPath(cfg.EventLogPath)
	}

	maxSize := cfg.MaxSizeMB
	if maxSize <= 0 {
		maxSize = 10
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	jsonEnc := zapcore.NewJSONEncoder(encCfg)
	consoleEnc := zapcore.NewConsoleEncoder(encCfg)

	var ws zapcore.WriteSyncer
	if cfg.Rotate {
		ws = zapcore.AddSync(&lumberjack.Logger{
			Filename:   path,
			MaxSize:    maxSize,
			MaxBackups: 5,
		})
	} else {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		ws = zapcore.AddSync(f)
	}

	fileCore := zapcore.NewCore(jsonEnc, ws, zapcore.InfoLevel)
	cores := []zapcore.Core{fileCore}
	if !cfg.Quiet {
		cores = append(cores, zapcore.NewCore(consoleEnc, zapcore.AddSync(os.Stderr), zapcore.InfoLevel))
	}

	core := zapcore.NewTee(cores...)
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	mu.Lock()
	sugar = logger.Sugar()
	underlying = logger
	mu.Unlock()
	return nil
}

// Zap 返回全局 *zap.Logger，适合结构化字段（zap.String(...)）；热路径上通常比 SugaredLogger 更省分配。
func Zap() *zap.Logger {
	mu.RLock()
	defer mu.RUnlock()
	if underlying != nil {
		return underlying
	}
	return defaultSugar.Desugar()
}

// NamedZap 等价于 Zap().Named(name)，name 为空时为 "default"。
func NamedZap(name string) *zap.Logger {
	if name == "" {
		name = "default"
	}
	return Zap().Named(name)
}

// Sugar 返回全局 SugaredLogger（Init 之后为文件为主；未 Init 时为 stderr 控制台）。
func Sugar() *zap.SugaredLogger {
	mu.RLock()
	defer mu.RUnlock()
	if sugar == nil {
		return defaultSugar
	}
	return sugar
}

// Named 返回带子 logger 名称的 SugaredLogger（zap 会带上 logger 字段，便于区分组件）。
// name 为空时使用 "default"。
func Named(name string) *zap.SugaredLogger {
	if name == "" {
		name = "default"
	}
	return Sugar().Named(name)
}

// Sync 刷新底层缓冲（进程退出前建议调用）。
func Sync() {
	mu.RLock()
	l := underlying
	mu.RUnlock()
	if l != nil {
		_ = l.Sync()
	}
}
