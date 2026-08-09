package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sakullla/sakullla-plugins/internal/buildkit"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nre-market:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("nre-market", flag.ContinueOnError)
	input := flags.String("input", "", "JSON release projection")
	output := flags.String("output", "", "market.yaml output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || *output == "" || flags.NArg() != 0 {
		return fmt.Errorf("--input and --output are required")
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	var market buildkit.Market
	decoderErr := json.Unmarshal(data, &market)
	if decoderErr != nil {
		return decoderErr
	}
	canonical, err := buildkit.RenderMarket(market)
	if err != nil {
		return err
	}
	if existing, readErr := os.ReadFile(*output); readErr == nil && string(existing) == string(canonical) {
		return nil
	}
	return os.WriteFile(*output, canonical, 0o644)
}
