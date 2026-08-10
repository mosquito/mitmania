package control

import (
	"embed"
	"net/http"
)

//go:embed static/index.html
var staticFS embed.FS

// spaHandler serves the embedded single-page admin UI: rule management
// and live stats, since driving the JSON API by hand isn't pleasant.
// There's exactly one page (no client-side routing, no build step) —
// http.FileServerFS is overkill for that, so this just serves the one
// embedded file directly for any GET that isn't a more specific route
// registered ahead of it in the mux.
func spaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "control: embedded SPA missing", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})
}
