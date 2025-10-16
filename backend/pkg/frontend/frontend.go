package frontend

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed swagger/*
var swaggerFile embed.FS

//go:embed dist/*
var staticSite embed.FS

// StaticFilesHandler serves static file from SPA React app
func StaticFilesHandler() http.HandlerFunc {
	distFS, err := fs.Sub(staticSite, "dist")
	if err != nil {
		panic(err)
	}

	fileServer := http.FileServer(http.FS(distFS))
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/inspect":
			r.URL.Path = "/"
		}

		fileServer.ServeHTTP(w, r)
	}
}

func SwaggerHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, _ := swaggerFile.ReadFile("swagger/swagger.json")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}
}
