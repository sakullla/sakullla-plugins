package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/buildkit"
	"github.com/sakullla/sakullla-plugins/internal/ci/common"
	"github.com/sakullla/sakullla-plugins/internal/ci/performance"
	cirelease "github.com/sakullla/sakullla-plugins/internal/ci/release"
	ciwasm "github.com/sakullla/sakullla-plugins/internal/ci/wasm"
	"github.com/sakullla/sakullla-plugins/internal/pluginmanifest"
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
		update := flags.Bool("update", false, "resolve the configured SDK selector and atomically refresh lock, module, and Rust projection")
		tag := flags.String("tag", "", "canonical plugin-sdk/v* tag selected during --update")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected sdk arguments: %v", flags.Args())
		}
		absoluteLock, err := filepath.Abs(*lockPath)
		if err != nil {
			return err
		}
		if *update {
			if err := updateSDKLock(ctx, absoluteLock, *tag); err != nil {
				return err
			}
		} else if *tag != "" {
			return fmt.Errorf("--tag requires --update")
		}
		lock, err := sdklock.Load(absoluteLock)
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
	case "all":
		return checkAll(ctx, args[1:])
	case "release":
		return checkRelease(ctx, args[1:])
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
		flags := flag.NewFlagSet("license", flag.ContinueOnError)
		root := flags.String("root", ".", "repository root")
		update := flags.Bool("update", false, "regenerate reviewed dependency inventories")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected license arguments: %v", flags.Args())
		}
		if *update {
			if err := updateLegalInventory(*root); err != nil {
				return err
			}
		}
		if err := checkLicenses(*root); err != nil {
			return err
		}
		return cirelease.ValidateLegalInventory(*root)
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
		return common.CheckReproducibleInPlace(ctx, *root, *output, command[0], command[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func updateSDKLock(ctx context.Context, lockPath, tag string) (returnErr error) {
	repositoryRoot := filepath.Dir(lockPath)
	repositoryLock, err := acquireSDKUpdateLock(ctx, repositoryRoot)
	if err != nil {
		return err
	}
	defer joinSDKUpdateLockClose(&returnErr, repositoryLock)
	if err := recoverSDKUpdateWithFS(repositoryRoot, osSDKTransactionFS{}); err != nil {
		return fmt.Errorf("recover interrupted SDK update: %w", err)
	}
	lock, err := sdklock.Read(lockPath)
	if err != nil {
		return err
	}
	if tag != "" {
		if !strings.HasPrefix(tag, "plugin-sdk/v") {
			return fmt.Errorf("SDK update tag must be canonical plugin-sdk/v*")
		}
		lock.Repository.Tag = tag
		lock.Repository.Branch = ""
	}
	lock = sdklock.RequireHTTPBackendProvider(lock)
	refreshed, err := sdklock.Refresh(ctx, lock)
	if err != nil {
		return err
	}
	version, err := sdklock.ModuleVersion(refreshed)
	if err != nil {
		return err
	}
	stagingRoot, err := os.MkdirTemp("", "sakullla-sdk-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagingRoot)
	for _, relative := range []string{"go.mod", "go.sum", "internal/ci/sdk/cmd/generate-policy-rust/main.go"} {
		if err := copySDKUpdateFile(repositoryRoot, stagingRoot, relative); err != nil {
			return err
		}
	}
	stagedSum := filepath.Join(stagingRoot, "go.sum")
	if err := removeModuleSums(stagedSum, refreshed.SDK.ModulePath); err != nil {
		return err
	}
	for _, invocation := range [][]string{
		{"mod", "edit", "-require=" + refreshed.SDK.ModulePath + "@" + version},
		{"mod", "download", refreshed.SDK.ModulePath + "@" + version},
		{"run", "./internal/ci/sdk/cmd/generate-policy-rust", "--output", "crates/nre-policy-guest/src/abi_generated.rs"},
	} {
		command := exec.CommandContext(ctx, "go", invocation...)
		command.Dir = stagingRoot
		command.Env = cleanGoEnvironment()
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("refresh SDK repository projection with go %s: %w: %s", strings.Join(invocation, " "), err, output)
		}
	}
	stagedLock := filepath.Join(stagingRoot, "sdk.lock.json")
	if err := sdklock.Write(stagedLock, refreshed); err != nil {
		return err
	}
	if err := sdklock.VerifyModuleIdentity(stagingRoot, refreshed); err != nil {
		return err
	}
	if _, err := sdklock.Verify(ctx, refreshed, true, stagingRoot); err != nil {
		return fmt.Errorf("verify staged SDK update: %w", err)
	}
	return promoteSDKUpdate(repositoryRoot, stagingRoot, sdkUpdateTargets)
}

func copySDKUpdateFile(sourceRoot, targetRoot, relative string) error {
	data, err := os.ReadFile(filepath.Join(sourceRoot, filepath.FromSlash(relative)))
	if err != nil {
		return fmt.Errorf("stage SDK update input %s: %w", relative, err)
	}
	target := filepath.Join(targetRoot, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o644)
}

func removeModuleSums(path, modulePath string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var kept []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] == modulePath {
			continue
		}
		if line != "" {
			kept = append(kept, line)
		}
	}
	return os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o644)
}

func cleanGoEnvironment() []string {
	blocked := map[string]bool{"GOENV": true, "GOFLAGS": true, "GOTOOLCHAIN": true, "GOWORK": true}
	environment := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !blocked[strings.ToUpper(key)] {
			environment = append(environment, entry)
		}
	}
	return append(environment, "GOENV=off", "GOFLAGS=", "GOTOOLCHAIN=local", "GOWORK=off")
}

type verifiedPlugin struct {
	id, version, runtime, abi, entry, artifactMode string
	manifest, artifact                             string
	extraFiles                                     map[string]string
}

func checkAll(ctx context.Context, args []string) error {
	_, _, err := buildAll(ctx, args, sdklock.Verify)
	return err
}

func buildAll(ctx context.Context, args []string, verify sdkVerifier) (sdklock.Lock, []verifiedPlugin, error) {
	return buildAllWithManifests(ctx, args, verify, false)
}

func buildAllForRelease(ctx context.Context, args []string, verify sdkVerifier) (sdklock.Lock, []verifiedPlugin, error) {
	return buildAllWithManifests(ctx, args, verify, true)
}

func buildAllWithManifests(ctx context.Context, args []string, verify sdkVerifier, bindBuiltArtifacts bool) (sdklock.Lock, []verifiedPlugin, error) {
	flags := flag.NewFlagSet("all", flag.ContinueOnError)
	lockPath := flags.String("sdk-lock", "sdk.lock.json", "canonical SDK lock")
	if err := flags.Parse(args); err != nil {
		return sdklock.Lock{}, nil, err
	}
	if flags.NArg() != 0 {
		return sdklock.Lock{}, nil, fmt.Errorf("unexpected all arguments: %v", flags.Args())
	}
	absoluteLock, err := filepath.Abs(*lockPath)
	if err != nil {
		return sdklock.Lock{}, nil, err
	}
	lock, err := sdklock.Load(absoluteLock)
	if err != nil {
		return sdklock.Lock{}, nil, err
	}
	root := filepath.Dir(absoluteLock)
	if _, err := verify(ctx, lock, true, root); err != nil {
		return sdklock.Lock{}, nil, fmt.Errorf("SDK release gate: %w", err)
	}
	if err := common.CheckGenerated(ctx, root); err != nil {
		return sdklock.Lock{}, nil, err
	}
	if err := checkLicenses(root); err != nil {
		return sdklock.Lock{}, nil, err
	}
	if err := cirelease.ValidateLegalInventory(root); err != nil {
		return sdklock.Lock{}, nil, err
	}
	if err := common.CheckSecrets(root); err != nil {
		return sdklock.Lock{}, nil, err
	}
	entries, err := os.ReadDir(filepath.Join(root, "plugins"))
	if err != nil {
		return sdklock.Lock{}, nil, err
	}
	var ids []string
	for _, entry := range entries {
		if !entry.IsDir() || !validPluginID(entry.Name()) {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, "plugins", entry.Name(), "plugin.yaml")); err == nil {
			ids = append(ids, entry.Name())
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return sdklock.Lock{}, nil, fmt.Errorf("no plugin manifests found")
	}
	plugins := make([]verifiedPlugin, 0, len(ids))
	for _, id := range ids {
		spec, err := pluginArtifactSpecFor(root, id)
		if err != nil {
			return sdklock.Lock{}, nil, err
		}
		artifact, err := buildPluginArtifact(ctx, root, id, spec)
		if err != nil {
			return sdklock.Lock{}, nil, err
		}
		manifest := filepath.Join(root, "plugins", id, "plugin.yaml")
		metadata, err := releaseManifest(manifest, id, spec, artifact, bindBuiltArtifacts)
		if err != nil {
			return sdklock.Lock{}, nil, err
		}
		metadata.artifact = artifact
		plugins = append(plugins, metadata)
	}
	return lock, plugins, nil
}

func checkRelease(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("release", flag.ContinueOnError)
	verifyReproducible := flags.Bool("verify-reproducible", false, "rebuild the candidate in two isolated source copies")
	signerSpec := flags.String("signer", "", "external official signer provider, as env:NAME")
	lockPath := flags.String("sdk-lock", "sdk.lock.json", "canonical SDK lock")
	output := flags.String("output", filepath.ToSlash(filepath.Join("dist", "release-candidate")), "candidate output directory")
	commit := flags.String("commit", "", "full repository commit for isolated rebuilds")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *signerSpec == "" {
		return fmt.Errorf("release requires --signer env:NAME and no positional arguments")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("official release requires a linux-amd64 build host")
	}
	absoluteLock, err := filepath.Abs(*lockPath)
	if err != nil {
		return err
	}
	root := filepath.Dir(absoluteLock)
	repositoryCommit := *commit
	if repositoryCommit == "" {
		command := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD")
		value, err := command.Output()
		if err != nil {
			return fmt.Errorf("resolve release repository commit: %w", err)
		}
		repositoryCommit = strings.TrimSpace(string(value))
	}
	if *verifyReproducible {
		relativeLock, err := filepath.Rel(root, absoluteLock)
		if err != nil {
			return err
		}
		reproArgs := []string{"run", "./cmd/nre-ci", "release", "--signer", *signerSpec, "--sdk-lock", filepath.ToSlash(relativeLock), "--output", *output, "--commit", repositoryCommit}
		if err := common.CheckReproducible(ctx, root, *output, "go", reproArgs); err != nil {
			return err
		}
	}
	lock, plugins, err := buildAllForRelease(ctx, []string{"--sdk-lock", absoluteLock}, sdklock.Verify)
	if err != nil {
		return err
	}
	signer, validator, err := cirelease.LoadProvider(*signerSpec)
	if err != nil {
		return err
	}
	absoluteOutput := *output
	if !filepath.IsAbs(absoluteOutput) {
		absoluteOutput = filepath.Join(root, filepath.FromSlash(absoluteOutput))
	}
	staging, err := makeReleaseStaging(absoluteOutput)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	packages := make([]cirelease.Package, 0, len(plugins))
	for _, plugin := range plugins {
		packageDirectory := filepath.Join(staging, plugin.id, plugin.version)
		result, err := buildkit.BuildPackage(ctx, buildkit.PackageRequest{
			ManifestPath: plugin.manifest, ArtifactPath: plugin.artifact, ArtifactDestination: plugin.entry,
			ArtifactMode: plugin.artifactMode, ExtraFiles: plugin.extraFiles,
			NoticePaths: []string{filepath.Join(root, "NOTICE"), filepath.Join(root, "THIRD_PARTY_LICENSES.json")},
			OutputDir:   packageDirectory, Signer: signer, Validator: strictPackageValidator{envelope: validator},
		})
		if err != nil {
			return fmt.Errorf("package %s: %w", plugin.id, err)
		}
		packages = append(packages, cirelease.Package{
			ID: plugin.id, Version: plugin.version, Runtime: plugin.runtime, ABI: plugin.abi,
			Directory: packageDirectory, PackageSHA256: result.PackageDigest, SignerIdentity: result.SignerIdentity,
		})
	}
	result, err := cirelease.AssembleContext(ctx, cirelease.Input{
		OutputDir: absoluteOutput, RepositoryCommit: repositoryCommit,
		SDKRepositoryCommit: lock.Repository.Commit, SDKDescriptorSHA256: lock.Artifacts.DescriptorSetSHA256,
		SDKABIs: []string{pluginsdk.PolicyABIV1, pluginsdk.RPCABIV1}, SignerIdentity: signer.Identity, Signer: signer, SignerPublicKey: officialReleasePublicKey(filepath.Join(root, "release", "official-ed25519-public-key.hex")),
		NoticePath: filepath.Join(root, "NOTICE"), ThirdPartyLicensesPath: filepath.Join(root, "THIRD_PARTY_LICENSES.json"),
		SBOMPath: filepath.Join(root, "SBOM.spdx.json"), GuidePath: filepath.Join(root, "AGENTS.md"), Packages: packages,
	})
	if err != nil {
		return err
	}
	if err := cirelease.PromoteMarket(result.OutputDir, filepath.Join(root, "market.yaml")); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(result.Provenance, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func officialReleasePublicKey(name string) ed25519.PublicKey {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(decoded)
}

func makeReleaseStaging(absoluteOutput string) (string, error) {
	parent := filepath.Dir(absoluteOutput)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, ".release-packages-")
}

func releaseManifest(path, expectedID string, spec pluginArtifactSpec, artifactFile string, bindBuiltArtifact bool) (verifiedPlugin, error) {
	manifest, err := pluginmanifest.Load(path)
	if err != nil {
		return verifiedPlugin{}, err
	}
	manifestPath := path
	if bindBuiltArtifact {
		bound, wire, err := pluginmanifest.RenderBuiltArtifactManifest(manifest, filepath.Dir(path), expectedID, artifactFile)
		if err != nil {
			return verifiedPlugin{}, fmt.Errorf("bind built artifact in %s: %w", path, err)
		}
		manifest = bound
		manifestPath = filepath.Join(filepath.Dir(artifactFile), "plugin.yaml")
		if err := os.WriteFile(manifestPath, wire, 0o644); err != nil {
			return verifiedPlugin{}, err
		}
	} else {
		if spec.kind == artifactWASMPolicy && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") {
			err = pluginmanifest.ValidateSourceContract(manifest, filepath.Dir(path), expectedID)
		} else {
			err = pluginmanifest.ValidateSource(manifest, filepath.Dir(path), expectedID, artifactFile)
		}
		if err != nil {
			return verifiedPlugin{}, fmt.Errorf("validate %s: %w", path, err)
		}
	}
	wantKind := pluginmanifest.RuntimeRPCService
	if spec.kind == artifactWASMPolicy {
		wantKind = pluginmanifest.RuntimeWASMPolicy
	}
	if manifest.Runtime.Kind != wantKind {
		return verifiedPlugin{}, fmt.Errorf("manifest %s runtime kind is %q, want %q", path, manifest.Runtime.Kind, wantKind)
	}
	destination, mode, err := pluginmanifest.ArtifactDestination(manifest)
	if err != nil {
		return verifiedPlugin{}, err
	}
	extraFiles := pluginmanifest.ExtraFiles(manifest, filepath.Dir(path))
	if spec.kind == artifactRPCService && spec.packageName != "" {
		wasmFile := filepath.Join(filepath.Dir(artifactFile), "plugin.wasm")
		for _, artifact := range manifest.Artifacts {
			if artifact.Path == destination || artifact.Mode != "wasm" {
				continue
			}
			extraFiles[artifact.Path] = wasmFile
		}
	}
	return verifiedPlugin{
		id: expectedID, version: manifest.Version, runtime: manifest.Runtime.Kind, abi: manifest.Runtime.ABI,
		entry: destination, artifactMode: mode, extraFiles: extraFiles,
		manifest: manifestPath,
	}, nil
}

type strictPackageValidator struct{ envelope buildkit.Validator }

func (validator strictPackageValidator) Validate(ctx context.Context, packageDir string) error {
	manifest, err := pluginmanifest.Load(filepath.Join(packageDir, "plugin.yaml"))
	if err != nil {
		return err
	}
	if err := pluginmanifest.ValidatePackageTree(packageDir, manifest); err != nil {
		return err
	}
	return validator.envelope.Validate(ctx, packageDir)
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
	spec, err := pluginArtifactSpecFor(repositoryRoot, *pluginID)
	if err != nil {
		return err
	}
	outputPath, err := buildPluginArtifact(ctx, repositoryRoot, *pluginID, spec)
	if err != nil {
		return err
	}
	fmt.Println(outputPath)
	return nil
}

type pluginArtifactKind uint8

const (
	artifactWASMPolicy pluginArtifactKind = iota + 1
	artifactRPCService
)

type pluginArtifactSpec struct {
	kind         pluginArtifactKind
	sourcePath   string
	packageName  string
	artifactName string
}

// pluginArtifactSpecFor is the explicit source/build allowlist. The canonical
// v1 manifest parser validates every plugin kind after its artifact is built.
func pluginArtifactSpecFor(repositoryRoot, pluginID string) (pluginArtifactSpec, error) {
	manifestPath := filepath.Join(repositoryRoot, "plugins", pluginID, "plugin.yaml")
	manifest, err := pluginmanifest.Load(manifestPath)
	if err != nil {
		return pluginArtifactSpec{}, err
	}
	if manifest.ID != pluginID {
		return pluginArtifactSpec{}, fmt.Errorf("plugin id %q does not match manifest id %q", pluginID, manifest.ID)
	}
	wantKind, wantABI, wantEntry := pluginmanifest.RuntimeRPCService, pluginmanifest.RPCABIV1, pluginID
	if pluginID == "ip-policy" || pluginID == "rate-limit" {
		wantKind, wantABI, wantEntry = pluginmanifest.RuntimeWASMPolicy, pluginmanifest.PolicyABIV1, filepath.ToSlash(filepath.Join("artifacts", pluginID+".wasm"))
	}
	if manifest.Runtime.Kind != wantKind {
		return pluginArtifactSpec{}, fmt.Errorf("plugin %q runtime kind %q is not %q", pluginID, manifest.Runtime.Kind, wantKind)
	}
	if manifest.Runtime.ABI != wantABI {
		return pluginArtifactSpec{}, fmt.Errorf("plugin %q ABI %q is not %q", pluginID, manifest.Runtime.ABI, wantABI)
	}
	if manifest.Runtime.Entry != wantEntry {
		return pluginArtifactSpec{}, fmt.Errorf("plugin %q entry %q is not %q", pluginID, manifest.Runtime.Entry, wantEntry)
	}
	if pluginID == "waf" {
		if err := requireOfficialWAFDualFace(manifest); err != nil {
			return pluginArtifactSpec{}, err
		}
	}
	if err := pluginmanifest.Validate(manifest, pluginID); err != nil {
		return pluginArtifactSpec{}, fmt.Errorf("validate %s: %w", manifestPath, err)
	}
	if err := pluginsdk.ValidateHTTPBackendProviderManifest(manifest); err != nil {
		return pluginArtifactSpec{}, fmt.Errorf("validate HTTP backend provider contract in %s: %w", manifestPath, err)
	}
	switch pluginID {
	case "ip-policy", "rate-limit":
		return pluginArtifactSpec{kind: artifactWASMPolicy, packageName: "sakullla-" + pluginID}, nil
	case "waf":
		return pluginArtifactSpec{kind: artifactRPCService, sourcePath: "./plugins/waf/cmd/waf", artifactName: "waf", packageName: "sakullla-waf"}, nil
	case "reverse-l4", "docker-app", "accelerator-sources", "doh", "cloudflare-dns", "shadowsocks-server", "webdav":
		return pluginArtifactSpec{kind: artifactRPCService, sourcePath: "./plugins/" + pluginID + "/cmd/" + pluginID, artifactName: pluginID}, nil
	default:
		return pluginArtifactSpec{}, fmt.Errorf("plugin id %q has no declared artifact source", pluginID)
	}
}

func requireOfficialWAFDualFace(manifest pluginmanifest.Manifest) error {
	if manifest.Runtime.HostScope != pluginsdk.HostScopeControlPlane {
		return fmt.Errorf("plugin waf host_scope %q is not control-plane", manifest.Runtime.HostScope)
	}
	if manifest.Runtime.PolicyKind != "waf" {
		return fmt.Errorf("plugin waf policy_kind %q is not waf", manifest.Runtime.PolicyKind)
	}
	policy := manifest.Runtime.Policy
	if policy == nil || policy.Kind != pluginmanifest.RuntimeWASMPolicy || policy.ABI != pluginmanifest.PolicyABIV1 || policy.HostScope != pluginsdk.HostScopeAgent {
		return errors.New("plugin waf requires a nested Agent wasm-policy")
	}
	if !officialWAFWASMPath(policy.Entry) {
		return fmt.Errorf("plugin waf nested wasm entry %q is not assets/waf.wasm or artifacts/waf.wasm", policy.Entry)
	}
	hasNative, hasWASM := false, false
	for _, artifact := range manifest.Artifacts {
		if artifact.Mode == "executable" {
			hasNative = true
		}
		if artifact.Mode == "wasm" && officialWAFWASMPath(artifact.Path) {
			hasWASM = true
		}
	}
	if !hasNative || !hasWASM {
		return errors.New("plugin waf requires native executable plus wasm artifacts")
	}
	projection, ok := pluginsdk.ProjectAgentPolicy(manifest)
	if !ok {
		return errors.New("plugin waf must project an Agent policy face")
	}
	if len(projection.ExtensionPoints) != 1 || projection.ExtensionPoints[0] != pluginsdk.ExtensionHTTPRequest {
		return errors.New("plugin waf PolicyStage must keep http.request and omit ui.route")
	}
	return nil
}

func officialWAFWASMPath(path string) bool {
	return path == "assets/waf.wasm" || path == "artifacts/waf.wasm"
}

func buildPluginArtifact(ctx context.Context, repositoryRoot, pluginID string, spec pluginArtifactSpec) (string, error) {
	if spec.kind == artifactRPCService {
		outputPath, err := buildRPCArtifact(ctx, repositoryRoot, pluginID, spec.sourcePath, spec.artifactName)
		if err != nil {
			return "", err
		}
		if spec.packageName != "" {
			if _, err := buildWASMArtifact(ctx, repositoryRoot, pluginID, spec); err != nil {
				return "", err
			}
		}
		return outputPath, nil
	}
	if spec.kind != artifactWASMPolicy {
		return "", fmt.Errorf("plugin %q has unknown artifact kind", pluginID)
	}
	return buildWASMArtifact(ctx, repositoryRoot, pluginID, spec)
}

func buildWASMArtifact(ctx context.Context, repositoryRoot, pluginID string, spec pluginArtifactSpec) (string, error) {
	cargo, err := cargoExecutable()
	if err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, cargo, "build", "-p", spec.packageName, "--target", "wasm32-unknown-unknown", "--release", "--locked")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build %s: %w\n%s", pluginID, err, output)
	}
	artifactPath := filepath.Join(cargoTargetDirectory(repositoryRoot), "wasm32-unknown-unknown", "release", strings.ReplaceAll(spec.packageName, "-", "_")+".wasm")
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return "", err
	}
	artifact, err = ciwasm.NormalizeEmptyFunctionTable(artifact)
	if err != nil {
		return "", err
	}
	if err := pluginsdk.ValidatePolicyV1WASM(artifact, pluginsdk.PolicyV1MaxMemoryBytes); err != nil {
		return "", err
	}
	outputDirectory := filepath.Join(repositoryRoot, "target", "nre-ci", pluginID)
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return "", err
	}
	outputPath := filepath.Join(outputDirectory, "plugin.wasm")
	if err := os.WriteFile(outputPath, artifact, 0o644); err != nil {
		return "", err
	}
	return outputPath, nil
}

func cargoTargetDirectory(repositoryRoot string) string {
	target := strings.TrimSpace(os.Getenv("CARGO_TARGET_DIR"))
	if target == "" {
		return filepath.Join(repositoryRoot, "target")
	}
	if filepath.IsAbs(target) {
		return filepath.Clean(target)
	}
	return filepath.Join(repositoryRoot, target)
}

func buildRPCArtifact(ctx context.Context, repositoryRoot, pluginID, sourcePath, artifactName string) (string, error) {
	outputDirectory := filepath.Join(repositoryRoot, "target", "nre-ci", pluginID)
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return "", err
	}
	outputPath := filepath.Join(outputDirectory, artifactName)
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", outputPath, sourcePath)
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build %s RPC artifact: %w\n%s", pluginID, err, output)
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		manifest, err := pluginmanifest.Load(filepath.Join(repositoryRoot, "plugins", pluginID, "plugin.yaml"))
		if err != nil {
			return "", fmt.Errorf("load %s RPC manifest identity: %w", pluginID, err)
		}
		validate := exec.CommandContext(ctx, outputPath, "--nre-ci-rpc-handshake", manifest.ID, manifest.Version)
		validate.Dir = repositoryRoot
		output, err := validate.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("validate %s RPC handshake: %w\n%s", pluginID, err, output)
		}
		if strings.TrimSpace(string(output)) != pluginsdk.RPCABIV1 {
			return "", fmt.Errorf("validate %s RPC handshake: got %q, want %q", pluginID, strings.TrimSpace(string(output)), pluginsdk.RPCABIV1)
		}
	}
	return outputPath, nil
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
