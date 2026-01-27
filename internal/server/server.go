package server

import (
	"net/http"
	"path"
	"strings"

	iofs "io/fs"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SetupRouter wires API routes and static assets.
func SetupRouter(webAssets iofs.FS, eventStream *EventHub) *gin.Engine {
	r := gin.Default()
	r.Use(cors.Default())

	api := r.Group("/api")
	{
		api.GET("/events", getEvents(eventStream))
		api.GET("/events/stream", streamEvents(eventStream))
		api.GET("/assets", listAssets(webAssets))
	}

	assets := webAssets
	if sub, err := iofs.Sub(webAssets, "web/dist"); err == nil {
		assets = sub
	}
	fileServer := http.FileServer(http.FS(assets))

	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api") {
			c.Status(http.StatusNotFound)
			return
		}

		reqPath := path.Clean(strings.TrimPrefix(c.Request.URL.Path, "/"))

		// 对于根路径、空路径或 index.html，让 FileServer 处理 "/"
		// FileServer 会自动查找 index.html
		if reqPath == "." || reqPath == "/" || reqPath == "" || reqPath == "index.html" {
			c.Request.URL.Path = "/"
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		// 检查文件是否存在
		file, err := assets.Open(reqPath)
		if err != nil {
			// 文件不存在，返回 index.html（SPA 路由回退）
			c.Request.URL.Path = "/"
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		stat, statErr := file.Stat()
		_ = file.Close()

		// 如果是目录，返回 index.html
		if statErr == nil && stat.IsDir() {
			c.Request.URL.Path = "/"
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		// 文件存在且不是目录，正常提供服务
		c.Request.URL.Path = "/" + reqPath
		fileServer.ServeHTTP(c.Writer, c.Request)
	})

	return r
}
