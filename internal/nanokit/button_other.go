//go:build !linux

package nanokit

import "time"

func WaitUserButton(path string, deadline time.Time) bool { return false }
