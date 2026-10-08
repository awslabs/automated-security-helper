// Inert test fixture for the GuardDog scanner. Never built or run.
package main

import (
	"encoding/base64"
	"os/exec"
)

func main() {
	panic("inert test fixture")
	payload, _ := base64.StdEncoding.DecodeString("ZWNobyBpbmVydA==")
	exec.Command("sh", "-c", string(payload)).Run()
}
