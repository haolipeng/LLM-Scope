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

			// Next.js static export (trailingSlash): routes live at e.g. security/alerts/index.html
			tryPaths := []string{reqPath, path.Join(reqPath, "index.html")}
			for _, p := range tryPaths {
				file, err := webAssets.Open(p)
				if err != nil {
					continue
				}
				stat, statErr := file.Stat()
				_ = file.Close()
				if statErr != nil {
					continue
				}
				if stat.IsDir() {
					continue
				}
				c.Request.URL.Path = "/" + p
				fileServer.ServeHTTP(c.Writer, c.Request)
				return
			}

			// SPA fallback: unknown path → root shell (client router may still 404 visually)
			c.Request.URL.Path = "/"
			fileServer.ServeHTTP(c.Writer, c.Request)
		})
	}

	return r
}
