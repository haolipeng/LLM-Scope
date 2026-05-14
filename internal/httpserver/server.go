package httpserver

import (
	"database/sql"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SetupRouter wires API routes and static assets.
func SetupRouter(webAssets fs.FS, analyticsDB *sql.DB) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(ginZapAccessLog())
	r.Use(cors.Default())

	api := r.Group("/api")
	{
		api.GET("/assets", listAssets(webAssets))
	}

	// Analytics routes (requires DuckDB)
	if analyticsDB != nil {
		registerAnalyticsRoutes(api, analyticsDB)
	}

	// Only serve static files when embedded assets are available
	if webAssets != nil {
		fileServer := http.FileServer(http.FS(webAssets))

		r.NoRoute(spaFallbackHandler(webAssets, fileServer))
	}

	return r
}

// spaFallbackHandler 处理前端 SPA 路由和静态文件服务
func spaFallbackHandler(webAssets fs.FS, fileServer http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api") {
			c.Status(http.StatusNotFound)
			return
		}

		reqPath := path.Clean(strings.TrimPrefix(c.Request.URL.Path, "/"))

		if reqPath == "." || reqPath == "/" || reqPath == "" || reqPath == "index.html" {
			c.Request.URL.Path = "/"
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		if tryServeStaticFile(c, webAssets, fileServer, reqPath) {
			return
		}

		// SPA fallback
		c.Request.URL.Path = "/"
		fileServer.ServeHTTP(c.Writer, c.Request)
	}
}

// tryServeStaticFile 尝试从静态资源中提供文件，找到返回 true
func tryServeStaticFile(c *gin.Context, webAssets fs.FS, fileServer http.Handler, reqPath string) bool {
	tryPaths := []string{reqPath, path.Join(reqPath, "index.html")}
	for _, p := range tryPaths {
		file, err := webAssets.Open(p)
		if err != nil {
			continue
		}
		stat, statErr := file.Stat()
		_ = file.Close()
		if statErr != nil || stat.IsDir() {
			continue
		}
		c.Request.URL.Path = "/" + p
		fileServer.ServeHTTP(c.Writer, c.Request)
		return true
	}
	return false
}
