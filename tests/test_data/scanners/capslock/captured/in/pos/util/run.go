// Package util holds small helpers.
package util

import "example.com/app/internal/exe"

// Run starts the named program.
func Run(name string) error {
	return exe.Start(name)
}
