// Package server serves the app over HTTP.
package server

import "net/http"

// Serve listens on addr with the default handler.
func Serve(addr string) error {
	return http.ListenAndServe(addr, nil)
}
