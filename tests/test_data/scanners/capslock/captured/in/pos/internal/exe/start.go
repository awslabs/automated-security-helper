// Package exe starts programs.
package exe

import "os/exec"

// Start starts the named program without waiting for it.
func Start(name string) error {
	return exec.Command(name).Start()
}
