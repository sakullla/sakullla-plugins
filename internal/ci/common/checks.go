package common

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const canonicalSDKModule = "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`)},
	{"AWS access key", regexp.MustCompile(`\bAKIA[A-Z0-9]{16}\b`)},
	{"assigned secret", regexp.MustCompile(`(?i)\b(?:api[_-]?key|client[_-]?secret|private[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{20,}`)},
}

func CheckSecrets(root string) error {
	var findings []string
	err := walkFiles(root, func(path, rel string) error {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.Size() > 4<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		for _, candidate := range secretPatterns {
			if candidate.pattern.Match(data) {
				findings = append(findings, rel+": "+candidate.name)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(findings) != 0 {
		sort.Strings(findings)
		return fmt.Errorf("secret-like material found:\n%s", strings.Join(findings, "\n"))
	}
	return nil
}

type LicensePolicy struct {
	Modules map[string]string
}

func CheckLicenses(root string, policy LicensePolicy) error {
	license, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		return fmt.Errorf("root LICENSE is required: %w", err)
	}
	if !bytes.Contains(license, []byte("GNU GENERAL PUBLIC LICENSE")) {
		return fmt.Errorf("root LICENSE is not GPL")
	}
	modules, err := requiredModules(filepath.Join(root, "go.mod"))
	if err != nil {
		return err
	}
	for _, module := range modules {
		if strings.HasPrefix(module, "github.com/sakullla/nginx-reverse-emby") && module != canonicalSDKModule {
			return fmt.Errorf("forbidden main-repository module dependency %q; use only %s", module, canonicalSDKModule)
		}
		licenseID, ok := policy.Modules[module]
		if !ok || strings.TrimSpace(licenseID) == "" {
			return fmt.Errorf("dependency %q has no reviewed license declaration", module)
		}
	}
	return checkGoImportBoundary(root)
}

func checkGoImportBoundary(root string) error {
	fileSet := token.NewFileSet()
	return walkFiles(root, func(path, rel string) error {
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse imports in %s: %w", rel, err)
		}
		for _, imported := range file.Imports {
			value := strings.Trim(imported.Path.Value, `"`)
			if strings.HasPrefix(value, "github.com/sakullla/nginx-reverse-emby/") &&
				value != canonicalSDKModule && !strings.HasPrefix(value, canonicalSDKModule+"/") {
				return fmt.Errorf("%s imports forbidden host implementation %q", rel, value)
			}
			if strings.HasPrefix(value, canonicalSDKModule+"/internal/") {
				return fmt.Errorf("%s imports non-public SDK implementation %q", rel, value)
			}
		}
		return nil
	})
}

func requiredModules(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var modules []string
	inBlock := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "//", 2)[0])
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			fields := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(fields) >= 1 {
				modules = append(modules, fields[0])
			}
			continue
		}
		if inBlock {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				modules = append(modules, fields[0])
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Strings(modules)
	return modules, nil
}

func CheckGenerated(ctx context.Context, root string) error {
	before, err := treeDigest(root)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "go", "generate", "./...")
	command.Dir = root
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("go generate failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	after, err := treeDigest(root)
	if err != nil {
		return err
	}
	if before != after {
		return fmt.Errorf("generated files drifted; run go generate ./... and commit the result")
	}
	return nil
}

func CheckReproducible(ctx context.Context, root, outputPath, commandName string, args []string) error {
	if commandName == "" || outputPath == "" {
		return fmt.Errorf("reproducibility command and declared output are required")
	}
	cleanOutput := filepath.Clean(outputPath)
	if filepath.IsAbs(cleanOutput) || cleanOutput == ".." || strings.HasPrefix(cleanOutput, ".."+string(filepath.Separator)) {
		return fmt.Errorf("declared output must stay within each clean checkout")
	}
	temporary, err := os.MkdirTemp("", "sakullla-reproducible-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	digests := make([]string, 2)
	for index := range digests {
		checkout := filepath.Join(temporary, fmt.Sprintf("checkout-%d", index+1))
		if err := copyRepository(root, checkout); err != nil {
			return err
		}
		command := exec.CommandContext(ctx, commandName, args...)
		command.Dir = checkout
		command.Env = append(os.Environ(),
			"GOTOOLCHAIN=local", "SOURCE_DATE_EPOCH=0", "TZ=UTC",
			"GOCACHE="+filepath.Join(temporary, fmt.Sprintf("go-cache-%d", index+1)),
			"CARGO_TARGET_DIR="+filepath.Join(temporary, fmt.Sprintf("cargo-target-%d", index+1)),
		)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("clean build %d failed: %w: %s", index+1, err, strings.TrimSpace(string(output)))
		}
		digests[index], err = outputDigest(filepath.Join(checkout, cleanOutput))
		if err != nil {
			return err
		}
	}
	if digests[0] != digests[1] {
		return fmt.Errorf("clean builds are not reproducible: %s != %s", digests[0], digests[1])
	}
	return nil
}
