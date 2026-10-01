package ingest

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

// NewStaticHandler serves the built web dashboard (web/dist) from dir as a
// single-page application: existing files are served as is, unknown paths
// without a file extension (client-side routes such as /alerts/123) get
// index.html, and API paths get a JSON 404 so a mistyped API call is never
// answered with HTML. Files are read through an os.Root, so requests cannot
// escape dir.
func NewStaticHandler(dir string) (http.Handler, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("web dashboard directory: %w", err)
	}
	fsys := root.FS()
	if _, err := fs.Stat(fsys, "index.html"); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("web dashboard directory %s has no index.html (run npm run build in web/): %w", dir, err)
	}
	files := http.FileServerFS(fsys)

	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, fsys, "index.html")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if isAPIPath(r.URL.Path) || r.URL.Path == "/ws" || strings.HasPrefix(r.URL.Path, "/ws/") {
			respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "error": "not found"})
			return
		}

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || name == "index.html" {
			serveIndex(w, r)
			return
		}
		if info, err := fs.Stat(fsys, name); err == nil && !info.IsDir() {
			files.ServeHTTP(w, r)
			return
		}
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r)
	}), nil
}
