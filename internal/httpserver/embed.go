package httpserver

import (
	"io/fs"
	"os"

	"github.com/haolipeng/LLM-Scope/internal/logging"

	"go.uber.org/zap"
)

// embeddedFS is set by the main package at init time.
var embeddedFS fs.FS

// SetEmbeddedFrontend sets the embedded frontend filesystem.
// The FS should contain an "out" subdirectory with the static assets.
func SetEmbeddedFrontend(f fs.FS) {
	embeddedFS = f
}

// WebAssets returns the filesystem for serving frontend static files.
// Priority: AGENTSIGHT_FRONTEND_DIR env var (dev/debug) > embedded FS.
func WebAssets() fs.FS {
	// Priority 1: environment variable (dev/debug mode)
	if dir := os.Getenv("AGENTSIGHT_FRONTEND_DIR"); dir != "" {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			logging.NamedZap("frontend").Warn("AGENTSIGHT_FRONTEND_DIR 不是有效目录，已忽略",
				zap.String("dir", dir))
		} else {
			logging.NamedZap("frontend").Info("从磁盘提供前端静态资源", zap.String("path", dir))
			return os.DirFS(dir)
		}
	}

	// Priority 2: embedded frontend assets
	if embeddedFS != nil {
		sub, err := fs.Sub(embeddedFS, "out")
		if err != nil {
			logging.NamedZap("frontend").Warn("无法访问内嵌前端资源", zap.Error(err))
			return nil
		}
		return sub
	}

	return nil
}
