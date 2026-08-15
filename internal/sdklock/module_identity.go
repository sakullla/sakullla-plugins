package sdklock

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// ModuleVersion returns the public Go module version selected by the immutable
// canonical SDK tag. Release identities deliberately do not accept branches or
// pseudo-versions: the module proxy and sdk.lock must name the same artifact.
func ModuleVersion(lock Lock) (string, error) {
	const prefix = "plugin-sdk/"
	if lock.Repository.Tag == "" || !strings.HasPrefix(lock.Repository.Tag, prefix) {
		return "", fmt.Errorf("SDK module identity requires a canonical plugin-sdk/v* tag")
	}
	version := strings.TrimPrefix(lock.Repository.Tag, prefix)
	if !strings.HasPrefix(version, "v") || strings.ContainsAny(version, " \\/") {
		return "", fmt.Errorf("SDK tag %q does not select a canonical Go module version", lock.Repository.Tag)
	}
	return version, nil
}

// VerifyModuleIdentity binds the immutable SDK lock to the root Go module and
// its authenticated checksums. It rejects stale SDK versions and local replace
// directives so clean release builds cannot consume a different contract.
func VerifyModuleIdentity(repositoryRoot string, lock Lock) error {
	wantVersion, err := ModuleVersion(lock)
	if err != nil {
		return err
	}
	goMod, err := os.ReadFile(filepath.Join(repositoryRoot, "go.mod"))
	if err != nil {
		return fmt.Errorf("read root go.mod for SDK identity: %w", err)
	}
	versions, err := moduleReferences(goMod, lock.SDK.ModulePath)
	if err != nil {
		return err
	}
	if len(versions) != 1 || versions[0] != wantVersion {
		return fmt.Errorf("root go.mod SDK identity = %v, want exactly %s@%s", versions, lock.SDK.ModulePath, wantVersion)
	}

	goSum, err := os.Open(filepath.Join(repositoryRoot, "go.sum"))
	if err != nil {
		return fmt.Errorf("read root go.sum for SDK identity: %w", err)
	}
	defer goSum.Close()
	foundModule, foundModFile := false, false
	var stale []string
	scanner := bufio.NewScanner(goSum)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || fields[0] != lock.SDK.ModulePath {
			continue
		}
		version := fields[1]
		baseVersion := strings.TrimSuffix(version, "/go.mod")
		if baseVersion != wantVersion {
			stale = append(stale, version)
			continue
		}
		if version == wantVersion {
			foundModule = true
		} else if version == wantVersion+"/go.mod" {
			foundModFile = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read root go.sum for SDK identity: %w", err)
	}
	if len(stale) != 0 {
		return fmt.Errorf("root go.sum contains stale SDK identities %v; want only %s", stale, wantVersion)
	}
	if !foundModule || !foundModFile {
		return fmt.Errorf("root go.sum must contain module and go.mod checksums for %s@%s", lock.SDK.ModulePath, wantVersion)
	}
	return nil
}

func moduleReferences(goMod []byte, modulePath string) ([]string, error) {
	parsed, err := modfile.Parse("go.mod", goMod, nil)
	if err != nil {
		return nil, fmt.Errorf("parse root go.mod for SDK identity: %w", err)
	}
	var versions []string
	for _, requirement := range parsed.Require {
		if requirement.Mod.Path == modulePath {
			versions = append(versions, requirement.Mod.Version)
		}
	}
	for _, replacement := range parsed.Replace {
		if replacement.Old.Path == modulePath {
			return nil, fmt.Errorf("root go.mod must not replace canonical SDK module %s", modulePath)
		}
	}
	return versions, nil
}
