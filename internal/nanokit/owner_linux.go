package nanokit

import (
	"os"
	"syscall"
)

func privateOwner(st os.FileInfo) bool {
	info, ok := st.Sys().(*syscall.Stat_t)
	return ok && info.Uid == uint32(os.Geteuid())
}
