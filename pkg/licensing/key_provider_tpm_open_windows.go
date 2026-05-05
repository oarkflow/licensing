//go:build windows

package licensing

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

func openTPM(_ string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
