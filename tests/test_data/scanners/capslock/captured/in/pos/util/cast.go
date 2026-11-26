package util

import "unsafe"

// FirstByte reads the first byte of n's memory.
func FirstByte(n *int) byte {
	return *(*byte)(unsafe.Pointer(n))
}
