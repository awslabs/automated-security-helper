// Package dep reads a file in an errgroup goroutine.
package dep

import (
	"os"

	"golang.org/x/sync/errgroup"
)

// Read reads path in a goroutine of an errgroup.
func Read(path string) error {
	var g errgroup.Group
	g.Go(func() error {
		_, err := os.ReadFile(path)
		return err
	})
	return g.Wait()
}
