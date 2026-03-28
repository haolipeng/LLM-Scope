package server

import (
	"fmt"
	"io/fs"
	"os"
)

// embeddedFS is set by the main package at init time.
var embeddedFS fs.FS

// SetEmbeddedFrontend sets the embedded frontend filesystem.
// The FS should contain an "out" subdirectory with the static assets.
func SetEmbeddedFrontend(f fs.FS) {
	embeddedFS = f
}

// WebAssets returns the filesystem for serving frontend static files.
// Priority: AGENTSIGHT_FRONTEND_DIR env var (dev/debug) > embedded FS.
func WebAssets() fs.FS {
	// Priority 1: environment variable (dev/debug mode)
	if dir := os.Getenv("AGENTSIGHT_FRONTEND_DIR"); dir != "" {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "WARNING: AGENTSIGHT_FRONTEND_DIR=%q is not a valid directory, ignoring\n", dir)
		} else {
			fmt.Fprintf(os.Stderr, "Serving frontend from disk: %s\n", dir)
			return os.DirFS(dir)
		}
	}

	// Priority 2: embedded frontend assets
	if embeddedFS != nil {
		sub, err := fs.Sub(embeddedFS, "out")
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: failed to access embedded frontend: %v\n", err)
			return nil
		}
		return sub
	}

	return nil
}
