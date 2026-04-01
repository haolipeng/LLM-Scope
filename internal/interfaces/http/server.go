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
func SetupRouter(webAssets fs.FS, eventStream *EventHub, analyticsDB *sql.DB) *gin.Engine {
	r := gin.Default()
	r.Use(cors.Default())

	api := r.Group("/api")
	{
		api.GET("/events", getEvents(eventStream))
		api.GET("/events/stream", streamEvents(eventStream))
		api.GET("/assets", listAssets(webAssets))
	}

	// Analytics routes (only when DuckDB is available)
	if analyticsDB != nil {
		registerAnalyticsRoutes(api, analyticsDB)
	}

	// Only serve static files when embedded assets are available
	if webAssets != nil {
		fileServer := http.FileServer(http.FS(webAssets))

		r.NoRoute(func(c *gin.Context) {
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

			file, err := webAssets.Open(reqPath)
			if err != nil {
				c.Request.URL.Path = "/"
				fileServer.ServeHTTP(c.Writer, c.Request)
				return
			}

			stat, statErr := file.Stat()
			_ = file.Close()

			if statErr == nil && stat.IsDir() {
				c.Request.URL.Path = "/"
				fileServer.ServeHTTP(c.Writer, c.Request)
				return
			}

			c.Request.URL.Path = "/" + reqPath
			fileServer.ServeHTTP(c.Writer, c.Request)
		})
	}

	return r
}
