package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: git-blob-digest REPOSITORY REVISION:PATH [...]")
		os.Exit(2)
	}
	for _, object := range os.Args[2:] {
		command := exec.Command("git", "-C", os.Args[1], "cat-file", "blob", object)
		data, err := command.Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", object, err)
			os.Exit(1)
		}
		fmt.Printf("%s  %s\n", strings.ToLower(fmt.Sprintf("%x", sha256.Sum256(data))), object)
	}
}
