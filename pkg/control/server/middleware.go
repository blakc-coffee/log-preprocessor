package server

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

// csp allows nothing but this origin. It is also the proof that the UI loads
// no external resource: a CDN font or script would be blocked and visible in
// the browser console.
const csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; " +
	"font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

var gzPool = sync.Pool{New: func() any { w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression); return w }}

type gzipWriter struct {
	http.ResponseWriter
	gz      *gzip.Writer
	decided bool
	on      bool
}

func compressible(ct string) bool {
	for _, p := range []string{"application/json", "text/", "application/javascript", "image/svg+xml"} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

func (g *gzipWriter) WriteHeader(code int) {
	if !g.decided {
		g.decided = true
		h := g.Header()
		g.on = code != http.StatusNoContent && code != http.StatusNotModified && h.Get("Content-Encoding") == "" && compressible(h.Get("Content-Type"))
		if g.on {
			h.Del("Content-Length")
			h.Set("Content-Encoding", "gzip")
			h.Add("Vary", "Accept-Encoding")
		}
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.decided {
		if g.Header().Get("Content-Type") == "" {
			g.Header().Set("Content-Type", http.DetectContentType(b))
		}
		g.WriteHeader(http.StatusOK)
	}
	if !g.on {
		return g.ResponseWriter.Write(b)
	}
	if g.gz == nil {
		g.gz = gzPool.Get().(*gzip.Writer)
		g.gz.Reset(g.ResponseWriter)
	}
	return g.gz.Write(b)
}

func (g *gzipWriter) close() {
	if g.gz != nil {
		_ = g.gz.Close()
		gzPool.Put(g.gz)
	}
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		g := &gzipWriter{ResponseWriter: w}
		defer g.close()
		next.ServeHTTP(g, r)
	})
}
