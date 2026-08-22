package main

import (
	"context"
	"fmt"
	"os"

	"github.com/sakullla/sakullla-plugins/plugins/webdav"
)

func main() {
	if err := webdav.RunEntrypoint(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "webdav:", err)
		os.Exit(1)
	}
}
