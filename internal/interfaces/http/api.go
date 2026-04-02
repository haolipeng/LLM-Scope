package httpserver

import (
	iofs "io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

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
