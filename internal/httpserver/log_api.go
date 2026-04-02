package httpserver

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/haolipeng/LLM-Scope/internal/logging"
	"go.uber.org/zap"
)

// respondInternalServerError 返回 500 JSON，并记录 zap（便于与文件日志关联排查）。
func respondInternalServerError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	logging.NamedZap("api").Error("handler",
		zap.Error(err),
		zap.String("path", c.Request.URL.Path),
		zap.String("method", c.Request.Method),
	)
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}
