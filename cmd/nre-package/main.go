package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sakullla/sakullla-plugins/internal/buildkit"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nre-package:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("nre-package", flag.ContinueOnError)
	source := flags.String("source", ".", "clean source directory used by the build command")
	buildCommand := flags.String("build-command", "", "artifact builder executable")
	var buildArgs stringFlags
	flags.Var(&buildArgs, "build-arg", "artifact builder argument (repeatable)")
	goVersion := flags.String("go-version", "1.27.0", "required Go version")
	rustVersion := flags.String("rust-version", "1.97.1", "required Rust version")
	protocVersion := flags.String("protoc-version", "32.0", "required protoc version")
	manifest := flags.String("manifest", "", "path to canonical plugin.yaml")
	artifact := flags.String("artifact", "", "path to the built artifact")
	notices := flags.String("notices", "LICENSE", "comma-separated NOTICE/license files")
	output := flags.String("output", "", "new output package directory")
	signerCommand := flags.String("signer-command", "", "external signer provider executable")
	signerIdentity := flags.String("signer-identity", "", "expected external signer identity")
	validatorCommand := flags.String("validator-command", "", "pinned validator executable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if *buildCommand != "" {
		toolchain := buildkit.Toolchain{GoVersion: *goVersion, RustVersion: *rustVersion, ProtocVersion: *protocVersion}
		if err := toolchain.Verify(ctx); err != nil {
			return err
		}
		output, err := buildkit.RunIsolated(ctx, buildkit.CommandSpec{Name: *buildCommand, Args: buildArgs, Dir: *source})
		if err != nil {
			return fmt.Errorf("artifact build failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	result, err := buildkit.BuildPackage(ctx, buildkit.PackageRequest{
		ManifestPath: *manifest,
		ArtifactPath: *artifact,
		NoticePaths:  splitList(*notices),
		OutputDir:    *output,
		Signer: buildkit.CommandSigner{
			Command: *signerCommand, Identity: *signerIdentity,
		},
		Validator: buildkit.CommandValidator{Command: *validatorCommand},
	})
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

type stringFlags []string

func (values *stringFlags) String() string { return strings.Join(*values, ",") }

func (values *stringFlags) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func splitList(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}
