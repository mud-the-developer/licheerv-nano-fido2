package nanokit

import (
	"encoding/binary"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func inputReadIOCTL(fd int, number uintptr, buffer []byte) bool {
	request := uintptr(2<<30) | uintptr(len(buffer))<<16 | uintptr('E')<<8 | number
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(&buffer[0])))
	runtime.KeepAlive(buffer)
	return errno == 0
}

// WaitUserButton reads the existing gpio-keys device without grabbing/re-exporting it.
func WaitUserButton(path string, deadline time.Time) bool {
	// input_event uses two 64-bit timeval members on these little-endian targets.
	if runtime.GOARCH != "riscv64" && runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return false
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return false
	}
	name := make([]byte, 128)
	capabilities := make([]byte, 96)
	keys := make([]byte, 96)
	if !inputReadIOCTL(fd, 0x06, name) || strings.TrimRight(string(name), "\x00") != "gpio-keys" ||
		!inputReadIOCTL(fd, 0x21, capabilities) || capabilities[UserButtonCode/8]&(1<<(UserButtonCode%8)) == 0 ||
		!inputReadIOCTL(fd, 0x18, keys) {
		return false
	}
	state := userButtonState{released: keys[UserButtonCode/8]&(1<<(UserButtonCode%8)) == 0}
	buffer := make([]byte, 24*8)
	for time.Now().Before(deadline) {
		n, err := syscall.Read(fd, buffer)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err != nil || n == 0 || n%24 != 0 {
			return false
		}
		for offset := 0; offset < n; offset += 24 {
			event := buffer[offset : offset+24]
			approve, fail := state.event(binary.LittleEndian.Uint16(event[16:18]), binary.LittleEndian.Uint16(event[18:20]), int32(binary.LittleEndian.Uint32(event[20:24])))
			if fail {
				return false
			}
			if approve {
				return time.Now().Before(deadline)
			}
		}
	}
	return false
}
