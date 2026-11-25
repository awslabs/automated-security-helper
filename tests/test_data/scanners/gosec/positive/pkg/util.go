package pkg

import "os"

// Read opens a path chosen by the caller (gosec G304).
func Read(name string) []byte {
	b, _ := os.ReadFile(name)
	return b
}

// Touch ignores the error from Close (gosec G104).
func Touch() {
	f, _ := os.Create("touched.txt")
	f.Close()
}
