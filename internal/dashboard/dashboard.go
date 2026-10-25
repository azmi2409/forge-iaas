// Package dashboard serves the forge-iaas web UI: embedded static
// HTML/CSS/JS (see web/) that calls the REST API. Read-first: it
// offers workspace/run browsing, redacted state views, and
// approve/discard buttons, but NO config editor. State shown here is
// always the API's redacted view; this package never touches raw state.
package dashboard

import (
	"net/http"

	"github.com/azmi2409/forge-iaas/web"
)

// Handler serves the dashboard at / (index.html) plus its JS/CSS.
// Mount it at / in the serve command; the API and MCP handlers own
// their own path prefixes and take precedence in the top-level mux.
func Handler() http.Handler {
	return http.FileServerFS(web.FS)
}
