package common

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type repositoryFile struct {
	path string
	rel  string
}

var skippedDirectories = map[string]bool{
	".git": true, ".idea": true, ".vscode": true, ".cache": true,
	"dist": true, "target": true, "coverage": true, "runtime-data": true,
}

func repositoryFiles(root string) ([]repositoryFile, error) {
	command := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	output, gitErr := command.Output()
	if gitErr == nil {
		seen := make(map[string]bool)
		var files []repositoryFile
		for _, item := range bytes.Split(output, []byte{0}) {
			if len(item) == 0 {
				continue
			}
			rel := filepath.ToSlash(filepath.Clean(string(item)))
			if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") || seen[rel] {
				return nil, fmt.Errorf("git returned invalid repository path %q", rel)
			}
			path := filepath.Join(root, filepath.FromSlash(rel))
			info, err := os.Lstat(path)
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("repository entry %q is not a regular file", rel)
			}
			seen[rel] = true
			files = append(files, repositoryFile{path: path, rel: rel})
		}
		sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
		return files, nil
	}
	var files []repositoryFile
	err := walkFiles(root, func(path, rel string) error {
		files = append(files, repositoryFile{path: path, rel: rel})
		return nil
	})
	return files, err
}

func walkFiles(root string, visit func(string, string) error) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			if skippedDirectories[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular repository entry %q", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		return visit(path, filepath.ToSlash(rel))
	})
}

func treeDigest(root string) (string, error) {
	return treeDigestExcluding(root, "")
}

func treeDigestExcluding(root, excludedPath string) (string, error) {
	excludedPath = filepath.ToSlash(filepath.Clean(excludedPath))
	if excludedPath == "." {
		excludedPath = ""
	}
	var records []string
	err := walkFiles(root, func(path, rel string) error {
		if excludedPath != "" && (rel == excludedPath || strings.HasPrefix(rel, excludedPath+"/")) {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		records = append(records, rel+"\x00"+info.Mode().String()+"\x00"+hex.EncodeToString(digest[:]))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(records)
	digest := sha256.Sum256([]byte(strings.Join(records, "\n")))
	return hex.EncodeToString(digest[:]), nil
}

func removeDeclaredOutput(root, relative string) error {
	if relative == "." {
		return fmt.Errorf("declared output must not be the repository root")
	}
	parent := filepath.Dir(relative)
	current := root
	if parent != "." {
		for _, component := range strings.Split(parent, string(filepath.Separator)) {
			current = filepath.Join(current, component)
			info, err := os.Lstat(current)
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("declared output parent %q is a symbolic link", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("declared output parent %q is not a directory", current)
			}
		}
	}
	target := filepath.Join(root, relative)
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("remove previous declared output %q: %w", target, err)
	}
	return nil
}

func outputDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().IsRegular() {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(data)
		return hex.EncodeToString(digest[:]), nil
	}
	if !info.IsDir() {
		return "", fmt.Errorf("declared output %q is not a regular file or directory", path)
	}
	var records []string
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == path || entry.IsDir() {
			return nil
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("declared output contains non-regular entry %q", current)
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		rel, err := filepath.Rel(path, current)
		if err != nil {
			return err
		}
		records = append(records, filepath.ToSlash(rel)+"\x00"+hex.EncodeToString(digest[:]))
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", fmt.Errorf("declared output %q is empty", path)
	}
	sort.Strings(records)
	digest := sha256.Sum256([]byte(strings.Join(records, "\n")))
	return hex.EncodeToString(digest[:]), nil
}

func copyRepository(source, destination string) error {
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	return walkFiles(source, func(path, rel string) error {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		mode := fs.FileMode(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}
