package httpserver

import (
	"io"
	iofs "io/fs"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// getEvents returns the log file contents as NDJSON text/plain.
// The file is streamed directly to the response to avoid loading it all into memory.
func getEvents(hub *EventHub) gin.HandlerFunc {
	return func(c *gin.Context) {
		logPath := hub.LogFile()
		if logPath == "" {
			c.Header("Content-Type", "text/plain")
			c.String(http.StatusOK, "")
			return
		}

		file, err := os.Open(logPath)
		if err != nil {
			// File may not exist yet (no events captured)
			c.Header("Content-Type", "text/plain")
			c.String(http.StatusOK, "")
			return
		}
		defer file.Close()

		c.Header("Content-Type", "text/plain")
		c.Status(http.StatusOK)
		io.Copy(c.Writer, file)
	}
}

// listAssets returns the embedded asset list (best-effort).
func listAssets(fs iofs.FS) gin.HandlerFunc {
	return func(c *gin.Context) {
		assets := []string{}
		if fs == nil {
			c.JSON(http.StatusOK, gin.H{"assets": assets, "total_count": 0})
			return
		}

		root, err := fs.Open(".")
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"assets": assets, "total_count": 0})
			return
		}
		defer root.Close()

		if dir, ok := root.(iofs.ReadDirFile); ok {
			items, _ := dir.ReadDir(-1)
			for _, item := range items {
				assets = append(assets, item.Name())
			}
		}

		c.JSON(http.StatusOK, gin.H{"assets": assets, "total_count": len(assets)})
	}
}

// streamEvents streams SSE events from the hub.
func streamEvents(hub *EventHub) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")

		stream := hub.Subscribe()
		defer hub.Unsubscribe(stream)

		c.Stream(func(w io.Writer) bool {
			select {
			case event, ok := <-stream:
				if !ok {
					return false
				}
				c.SSEvent("message", event)
				return true
			case <-c.Request.Context().Done():
				return false
			}
		})
	}
}
