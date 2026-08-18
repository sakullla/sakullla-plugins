package main

import (
	"context"
	"fmt"
	"os"

	shadowsocksserver "github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server"
	_ "github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server/web"
)

func main() {
	if err := shadowsocksserver.RunEntrypoint(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "shadowsocks-server:", err)
		os.Exit(1)
	}
}
