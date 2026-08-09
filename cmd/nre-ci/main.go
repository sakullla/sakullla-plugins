package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/ci/common"
	"github.com/sakullla/sakullla-plugins/internal/ci/performance"
	ciwasm "github.com/sakullla/sakullla-plugins/internal/ci/wasm"
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
		return fmt.Errorf("expected repository, generated, license, secret, reproducible, sdk, or plugin")
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
	case "plugin":
		return checkPlugin(ctx, args[1:])
	case "performance":
		return checkPerformance(ctx, args[1:])
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

func checkPerformance(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("performance", flag.ContinueOnError)
	profile := flags.String("profile", string(performance.ProfileRelease), "local or release evidence profile")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected performance arguments: %v", flags.Args())
	}

	var (
		summary performance.Summary
		err     error
	)
	switch performance.Profile(*profile) {
	case performance.ProfileLocal:
		summary, err = performance.RunLocalHarness(ctx)
	case performance.ProfileRelease:
		summary, err = performance.Run(ctx, performance.ProfileRelease, performance.CapabilityEvidence{}, nil, nil)
	default:
		return fmt.Errorf("unknown performance profile %q", *profile)
	}
	if err != nil {
		return err
	}
	encoded, err := performance.MarshalSummary(summary)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func checkPlugin(ctx context.Context, args []string) error {
	return checkPluginWithVerifier(ctx, args, sdklock.Verify)
}

type sdkVerifier func(context.Context, sdklock.Lock, bool, string) (sdklock.Verification, error)

func checkPluginWithVerifier(ctx context.Context, args []string, verify sdkVerifier) error {
	flags := flag.NewFlagSet("plugin", flag.ContinueOnError)
	pluginID := flags.String("id", "", "plugin identifier")
	lockPath := flags.String("sdk-lock", "sdk.lock.json", "canonical SDK lock")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected plugin arguments: %v", flags.Args())
	}
	if !validPluginID(*pluginID) {
		return fmt.Errorf("plugin id %q is invalid", *pluginID)
	}
	absoluteLock, err := filepath.Abs(*lockPath)
	if err != nil {
		return err
	}
	lock, err := sdklock.Load(absoluteLock)
	if err != nil {
		return err
	}
	if _, err := verify(ctx, lock, true, filepath.Dir(absoluteLock)); err != nil {
		return fmt.Errorf("SDK release gate: %w", err)
	}
	repositoryRoot := filepath.Dir(absoluteLock)
	cargo, err := cargoExecutable()
	if err != nil {
		return err
	}
	packageName := "sakullla-" + *pluginID
	command := exec.CommandContext(ctx, cargo, "build", "-p", packageName, "--target", "wasm32v1-none", "--release", "--locked")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %w\n%s", *pluginID, err, output)
	}
	artifactPath := filepath.Join(repositoryRoot, "target", "wasm32v1-none", "release", strings.ReplaceAll(packageName, "-", "_")+".wasm")
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return err
	}
	artifact, err = ciwasm.NormalizeEmptyFunctionTable(artifact)
	if err != nil {
		return err
	}
	if err := pluginsdk.ValidatePolicyV1WASM(artifact, pluginsdk.PolicyV1MaxMemoryBytes); err != nil {
		return err
	}
	outputDirectory := filepath.Join(repositoryRoot, "target", "nre-ci", *pluginID)
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return err
	}
	outputPath := filepath.Join(outputDirectory, "plugin.wasm")
	if err := os.WriteFile(outputPath, artifact, 0o644); err != nil {
		return err
	}
	fmt.Println(outputPath)
	return nil
}

func validPluginID(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return false
	}
	for _, current := range value {
		if (current < 'a' || current > 'z') && (current < '0' || current > '9') && current != '-' {
			return false
		}
	}
	return true
}

func cargoExecutable() (string, error) {
	if cargo, err := exec.LookPath("cargo"); err == nil {
		return cargo, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("cargo is required")
	}
	cargo := filepath.Join(home, ".cargo", "bin", "cargo")
	if runtime.GOOS == "windows" {
		cargo += ".exe"
	}
	if _, err := os.Stat(cargo); err != nil {
		return "", errors.New("cargo is required")
	}
	return cargo, nil
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
