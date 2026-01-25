package server

import "embed"

//go:embed web/dist/**
var webAssets embed.FS

func WebAssets() embed.FS {
	return webAssets
}
