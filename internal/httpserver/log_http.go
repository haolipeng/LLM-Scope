package httpserver

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/haolipeng/LLM-Scope/internal/logging"
	"go.uber.org/zap"
)

// ginZapAccessLog 记录 HTTP 访问（与 gin.Logger 类似，输出走统一 zap）。
func ginZapAccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		c.Next()
		logging.NamedZap("http").Info("access",
			zap.Int("status", c.Writer.Status()),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.Duration("latency", time.Since(start)),
			zap.Int("bytes", c.Writer.Size()),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}
