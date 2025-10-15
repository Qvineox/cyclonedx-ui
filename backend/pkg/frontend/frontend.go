package frontend

import (
	"embed"
	"io/fs"
	"net/http"
	"path/filepath"
)

//go:embed dist
var staticSite embed.FS

// StaticFilesHandler serves static file from SPA React app
func StaticFilesHandler() http.HandlerFunc {
	distFS, err := fs.Sub(staticSite, "dist")
	if err != nil {
		panic(err)
	}

	fileServer := http.FileServerFS(distFS)
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := distFS.Open(filepath.Join(r.URL.Path)); err != nil {
			r.URL.Path = "/"
		}

		fileServer.ServeHTTP(w, r)
	}

	//return http.FileServerFS(distFS)
}
