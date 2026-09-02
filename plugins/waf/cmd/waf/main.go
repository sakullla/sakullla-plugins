package main

import (
	"context"
	"fmt"
	"os"

	waf "github.com/sakullla/sakullla-plugins/plugins/waf"
)

func main() {
	if err := waf.RunEntrypoint(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "waf:", err)
		os.Exit(1)
	}
}
