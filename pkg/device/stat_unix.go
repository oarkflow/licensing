//go:build !windows

package device

import (
	"fmt"
	"os"
	"syscall"
)

func volumeIDFromFileInfo(info os.FileInfo, path string) string {
	if info == nil || info.Sys() == nil {
		return ""
	}
	sysStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("vol-%x-%x-%s", sysStat.Dev, sysStat.Ino, path)
}
