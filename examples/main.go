package main

import (
	"fmt"

	"github.com/oarkflow/licensing/pkg/device"
)

func main() {
	info, err := device.GetInfo()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", info.Fingerprint)
}
