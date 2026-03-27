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

	// Only serve static files when embedded assets are available
	if webAssets != nil {
		assets := webAssets
		if sub, err := iofs.Sub(webAssets, "web/dist"); err == nil {
			// Verify the sub-directory actually exists before using it
			if f, ferr := sub.Open("."); ferr == nil {
				f.Close()
				assets = sub
			}
		}
		fileServer := http.FileServer(http.FS(assets))

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

			file, err := assets.Open(reqPath)
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
