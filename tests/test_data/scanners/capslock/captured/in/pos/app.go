// Package app is the module root's own package.
package app

import "os"

// Mode reads the APP_MODE environment variable.
func Mode() string {
	return os.Getenv("APP_MODE")
}
