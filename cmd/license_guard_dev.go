//go:build !distribution

package main

import "context"

func runWithDistributionLicense(ctx context.Context, run func(context.Context)) {
	run(ctx)
}
