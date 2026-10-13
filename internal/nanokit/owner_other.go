//go:build !linux

package nanokit

import "os"

// File-backed deployment is Linux-only; never relax its ownership checks on Windows.
func privateOwner(st os.FileInfo) bool { return false }
