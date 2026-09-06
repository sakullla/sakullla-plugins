package main

import (
	"context"
	"fmt"
	"os"

	ippolicy "github.com/sakullla/sakullla-plugins/plugins/ip-policy"
)

func main() {
	if err := ippolicy.RunEntrypoint(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ip-policy:", err)
		os.Exit(1)
	}
}
