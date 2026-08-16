package buildkit

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const PackageBlobFormatV1 = "tar+gzip-v1"

type PackageBlob struct {
	Path   string
	SHA256 string
	Size   int64
}

// BuildPackageBlob creates the deterministic transport object used for
// on-demand downloads. Package identity remains the signed tree digest inside
// the archive; this raw blob digest protects transfer and storage.
func BuildPackageBlob(packageRoot, destination string) (PackageBlob, error) {
	var names []string
	err := filepath.WalkDir(packageRoot, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == packageRoot || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("package blob contains non-regular entry %q", name)
		}
		relative, err := filepath.Rel(packageRoot, name)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return PackageBlob{}, err
	}
	if len(names) == 0 {
		return PackageBlob{}, fmt.Errorf("package blob source is empty")
	}
	sort.Strings(names)
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return PackageBlob{}, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".package-blob-")
	if err != nil {
		return PackageBlob{}, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	hash := sha256.New()
	gzipWriter, err := gzip.NewWriterLevel(io.MultiWriter(temporary, hash), gzip.BestCompression)
	if err != nil {
		temporary.Close()
		return PackageBlob{}, err
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	for _, relative := range names {
		name := filepath.Join(packageRoot, filepath.FromSlash(relative))
		info, err := os.Stat(name)
		if err != nil {
			return PackageBlob{}, closeBlobWriters(tarWriter, gzipWriter, temporary, err)
		}
		mode := int64(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		header := &tar.Header{Name: relative, Mode: mode, Size: info.Size(), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := tarWriter.WriteHeader(header); err != nil {
			return PackageBlob{}, closeBlobWriters(tarWriter, gzipWriter, temporary, err)
		}
		file, err := os.Open(name)
		if err != nil {
			return PackageBlob{}, closeBlobWriters(tarWriter, gzipWriter, temporary, err)
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return PackageBlob{}, closeBlobWriters(tarWriter, gzipWriter, temporary, fmt.Errorf("copy package blob file: %v %v", copyErr, closeErr))
		}
	}
	if err := closeBlobWriters(tarWriter, gzipWriter, temporary, nil); err != nil {
		return PackageBlob{}, err
	}
	info, err := os.Stat(temporaryName)
	if err != nil {
		return PackageBlob{}, err
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return PackageBlob{}, err
	}
	return PackageBlob{Path: destination, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: info.Size()}, nil
}

func closeBlobWriters(tarWriter *tar.Writer, gzipWriter *gzip.Writer, file *os.File, cause error) error {
	return errorsJoin(cause, tarWriter.Close(), gzipWriter.Close(), file.Close())
}

func errorsJoin(values ...error) error {
	var result error
	for _, value := range values {
		if value == nil {
			continue
		}
		if result == nil {
			result = value
		} else {
			result = fmt.Errorf("%v; %w", result, value)
		}
	}
	return result
}
