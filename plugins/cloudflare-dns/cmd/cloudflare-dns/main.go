package main

import (
	"context"
	"fmt"
	"os"

	cloudflaredns "github.com/sakullla/sakullla-plugins/plugins/cloudflare-dns"
)

func main() {
	if err := cloudflaredns.RunEntrypoint(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "cloudflare-dns:", err)
		os.Exit(1)
	}
}
