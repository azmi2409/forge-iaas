// Package web embeds the forge-iaas dashboard's static files.
// Plain HTML/CSS/JS only: no framework, no build step. The files are
// served by internal/dashboard; the JS talks to the REST API only.
package web

import "embed"

// FS holds index.html, app.js, and style.css.
//
//go:embed index.html app.js style.css
var FS embed.FS
