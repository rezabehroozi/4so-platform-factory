package webconsole

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"time"
)

//go:embed static/*
var content embed.FS

func Handler() http.Handler {
	sub, _ := fs.Sub(content, "static")
	files := http.FileServer(http.FS(sub))
	index, _ := fs.ReadFile(sub, "index.html")
	index = bytes.Replace(index,
		[]byte(`<script src="/app.js"></script>`),
		[]byte(`<script src="/app.js"></script><script src="/resource-explorer.js"></script>`),
		1,
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
			return
		}
		files.ServeHTTP(w, r)
	})
}
