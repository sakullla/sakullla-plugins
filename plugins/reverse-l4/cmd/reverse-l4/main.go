package main

import (
	"context"
	"fmt"
	"os"

	reversel4 "github.com/sakullla/sakullla-plugins/plugins/reverse-l4"
)

func main() {
	if err := reversel4.RunEntrypoint(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "reverse-l4:", err)
		os.Exit(1)
	}
}
