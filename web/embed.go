// Package web embeds the built single-page admin UI so the entire application
// ships as one self-contained binary. The Vite build outputs into dist/.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// Assets returns the built SPA file system rooted at dist/.
func Assets() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}
