package main

import (
	"context"
	"fmt"
	"os"

	acceleratorsources "github.com/sakullla/sakullla-plugins/plugins/accelerator-sources"
)

func main() {
	if err := acceleratorsources.RunEntrypoint(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "accelerator-sources:", err)
		os.Exit(1)
	}
}
