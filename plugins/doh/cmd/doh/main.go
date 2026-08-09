package main

import (
	"context"
	"fmt"
	"os"

	"github.com/sakullla/sakullla-plugins/plugins/doh"
)

func main() {
	if err := doh.RunEntrypoint(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "doh:", err)
		os.Exit(1)
	}
}
