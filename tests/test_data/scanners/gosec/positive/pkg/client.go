package pkg

import (
	"crypto/tls"
	"net/http"
)

// Client turns off certificate verification (gosec G402, HIGH).
func Client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
