package frontend

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed dist/*
var staticSite embed.FS

// StaticFilesHandler serves static file from SPA React app
func StaticFilesHandler() http.HandlerFunc {
	distFS, err := fs.Sub(staticSite, "dist")
	if err != nil {
		panic(err)
	}

	fileServer := http.FileServer(http.FS(distFS))
	return fileServer.ServeHTTP

	//return func(w http.ResponseWriter, r *http.Request) {
	//	path_ := path.Join("dist", r.URL.Path)
	//
	//	if _, err := distFS.Open(path_); err != nil {
	//		r.URL.Path = "/"
	//	}
	//
	//	fileServer.ServeHTTP(w, r)
	//}
}
