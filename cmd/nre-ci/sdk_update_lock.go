package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const sdkUpdateLockName = "nre-sdk-update.lock"

type sdkUpdateLock struct {
	file   *os.File
	unlock func(*os.File) error
	close  func(*os.File) error
}

func acquireSDKUpdateLock(ctx context.Context, repositoryRoot string) (*sdkUpdateLock, error) {
	lockPath, err := sdkUpdateLockPath(repositoryRoot)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open SDK update lock: %w", err)
	}
	for {
		acquired, err := trySDKUpdateFileLock(file)
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("acquire SDK update lock: %w", err)
		}
		if acquired {
			return &sdkUpdateLock{
				file:   file,
				unlock: unlockSDKUpdateFile,
				close:  (*os.File).Close,
			}, nil
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = file.Close()
			return nil, fmt.Errorf("wait for SDK update lock: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func (lock *sdkUpdateLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := lock.unlock(lock.file)
	closeErr := lock.close(lock.file)
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}

func joinSDKUpdateLockClose(returnErr *error, lock *sdkUpdateLock) {
	*returnErr = errors.Join(*returnErr, lock.Close())
}

func sdkUpdateLockPath(repositoryRoot string) (string, error) {
	absoluteRoot, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return "", err
	}
	metadataPath := filepath.Join(absoluteRoot, ".git")
	metadata, err := os.Stat(metadataPath)
	if err != nil {
		return "", fmt.Errorf("resolve SDK update Git metadata: %w", err)
	}
	gitDirectory := metadataPath
	if !metadata.IsDir() {
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			return "", fmt.Errorf("read SDK update Git metadata: %w", err)
		}
		line := strings.TrimSpace(string(data))
		if strings.ContainsAny(line, "\r\n") {
			return "", fmt.Errorf("parse SDK update Git metadata: expected one gitdir line")
		}
		key, value, found := strings.Cut(line, ":")
		if !found || key != "gitdir" || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("parse SDK update Git metadata: expected gitdir: <path>")
		}
		gitDirectory = strings.TrimSpace(value)
		if !filepath.IsAbs(gitDirectory) {
			gitDirectory = filepath.Join(absoluteRoot, gitDirectory)
		}
	}
	gitDirectory, err = filepath.EvalSymlinks(gitDirectory)
	if err != nil {
		return "", fmt.Errorf("resolve SDK update Git directory: %w", err)
	}
	metadata, err = os.Stat(gitDirectory)
	if err != nil {
		return "", fmt.Errorf("stat SDK update Git directory: %w", err)
	}
	if !metadata.IsDir() {
		return "", fmt.Errorf("SDK update Git metadata is not a directory: %s", gitDirectory)
	}
	return filepath.Join(filepath.Clean(gitDirectory), sdkUpdateLockName), nil
}
