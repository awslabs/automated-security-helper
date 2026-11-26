// Package store reads stored records.
package store

import "os"

// Load returns the bytes of the record at path.
func Load(path string) ([]byte, error) {
	return os.ReadFile(path)
}
