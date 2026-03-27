package server

import (
	"fmt"
	iofs "io/fs"
	"os"
)

// WebAssets returns the filesystem for serving frontend static files.
// When AGENTSIGHT_FRONTEND_DIR is set, it reads from disk (dev mode);
// otherwise returns nil (frontend runs independently).
func WebAssets() iofs.FS {
	if dir := os.Getenv("AGENTSIGHT_FRONTEND_DIR"); dir != "" {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "WARNING: AGENTSIGHT_FRONTEND_DIR=%q is not a valid directory, ignoring\n", dir)
			return nil
		}
		fmt.Fprintf(os.Stderr, "Serving frontend from disk: %s\n", dir)
		return os.DirFS(dir)
	}
	return nil
}
