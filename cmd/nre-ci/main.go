package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sakullla/sakullla-plugins/internal/ci/common"
	"github.com/sakullla/sakullla-plugins/internal/sdklock"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nre-ci:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("expected repository, generated, license, secret, reproducible, or sdk")
	}
	switch args[0] {
	case "sdk":
		flags := flag.NewFlagSet("sdk", flag.ContinueOnError)
		lockPath := flags.String("lock", "sdk.lock.json", "canonical SDK lock")
		requireCapabilities := flags.Bool("require-host-capabilities", false, "fail when any required host capability is unavailable")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected sdk arguments: %v", flags.Args())
		}
		lock, err := sdklock.Load(*lockPath)
		if err != nil {
			return err
		}
		absoluteLock, err := filepath.Abs(*lockPath)
		if err != nil {
			return err
		}
		verification, err := sdklock.Verify(ctx, lock, *requireCapabilities, filepath.Dir(absoluteLock))
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(verification, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
		return nil
	case "repository":
		root, err := rootFlag("repository", args[1:])
		if err != nil {
			return err
		}
		if err := common.CheckGenerated(ctx, root); err != nil {
			return err
		}
		if err := checkLicenses(root); err != nil {
			return err
		}
		return common.CheckSecrets(root)
	case "generated":
		root, err := rootFlag("generated", args[1:])
		if err != nil {
			return err
		}
		return common.CheckGenerated(ctx, root)
	case "license":
		root, err := rootFlag("license", args[1:])
		if err != nil {
			return err
		}
		return checkLicenses(root)
	case "secret":
		root, err := rootFlag("secret", args[1:])
		if err != nil {
			return err
		}
		return common.CheckSecrets(root)
	case "reproducible":
		flags := flag.NewFlagSet("reproducible", flag.ContinueOnError)
		root := flags.String("root", ".", "repository root")
		output := flags.String("output", "", "declared artifact file or directory relative to each clean checkout")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		command := flags.Args()
		if len(command) == 0 {
			return fmt.Errorf("reproducible requires a command after --")
		}
		return common.CheckReproducible(ctx, *root, *output, command[0], command[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func rootFlag(name string, args []string) (string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 {
		return "", fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	return *root, nil
}

func checkLicenses(root string) error {
	policy, err := common.DefaultLicensePolicy()
	if err != nil {
		return err
	}
	return common.CheckLicenses(root, policy)
}
