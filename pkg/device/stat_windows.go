//go:build windows

package device

import "os"

func volumeIDFromFileInfo(_ os.FileInfo, _ string) string {
	return ""
}
