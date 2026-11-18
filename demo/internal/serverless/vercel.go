//go:build vercel

package serverless

import (
	"net/http"

	"github.com/vercel/go-bridge/go/bridge"
)

// Start serves a handler using Vercel's request format.
func Start(handler http.Handler) {
	bridge.Start(handler)
}
