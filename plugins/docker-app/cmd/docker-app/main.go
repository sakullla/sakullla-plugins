package main

import (
	"context"
	"fmt"
	"os"

	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func main() {
	if err := dockerapp.RunEntrypoint(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "docker-app:", err)
		os.Exit(1)
	}
}
