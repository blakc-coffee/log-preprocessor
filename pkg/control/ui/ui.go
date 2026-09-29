// Package ui embeds the built frontend (frontend/dist, copied here by
// `make ui`) and serves it as a single-page app.
//
// Hashed files under /assets/ are immutable and cached for a year;
// index.html is never cached, so a new build is picked up on reload. Any
// other path that is not a file serves index.html, so deep links such as
// /events/7.cisco_asa@1.0.0 work. /api/ is never answered here.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Dist is the embedded build output.
func Dist() fs.FS {
	sub, _ := fs.Sub(dist, "dist")
	return sub
}

const notBuilt = `<!doctype html><meta charset="utf-8"><title>ULPF control plane</title>
<body style="background:#000;color:#fff;font:14px system-ui;padding:24px">
<p>The UI has not been built into this binary. Run <code>make ui</code>, then rebuild.</p>
<p>The control API is available under <code>/api/</code>.</p>`

var staticExt = map[string]bool{".js": true, ".css": true, ".map": true, ".woff2": true, ".woff": true, ".svg": true,
	".png": true, ".ico": true, ".webmanifest": true, ".txt": true}

// Handler serves files from root with SPA fallback.
func Handler(root fs.FS) http.Handler {
	files := http.FileServerFS(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if strings.HasPrefix(p, "api/") || p == "api" {
			http.NotFound(w, r)
			return
		}
		if p != "" && p != "index.html" {
			if st, err := fs.Stat(root, p); err == nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				files.ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(p, "assets/") || staticExt[path.Ext(p)] {
				// A missing asset is a 404, never the HTML shell: serving
				// index.html as a script would fail confusingly. Other dotted
				// paths are app routes (event ids contain dots).
				http.NotFound(w, r)
				return
			}
		}
		index, err := fs.ReadFile(root, "index.html")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(notBuilt))
			return
		}
		_, _ = w.Write(index)
	})
}
