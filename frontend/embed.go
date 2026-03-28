package frontend

import "embed"

// DistFS holds the static frontend assets built by Next.js (the "out/" directory).
//
//go:embed all:out
var DistFS embed.FS
