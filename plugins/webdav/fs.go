package webdav

import (
	"context"
	"errors"
	"os"
	"sync/atomic"

	xwebdav "golang.org/x/net/webdav"
)

type shareFS struct {
	root string
}

type conditionalCreateContextKey struct{}

type conditionalCreateState struct {
	targetExists atomic.Bool
}

func withConditionalCreate(ctx context.Context) (context.Context, *conditionalCreateState) {
	state := &conditionalCreateState{}
	return context.WithValue(ctx, conditionalCreateContextKey{}, state), state
}

func (state *conditionalCreateState) preconditionFailed() bool {
	return state != nil && state.targetExists.Load()
}

func (fs shareFS) resolve(name string) (string, error) {
	return resolveInsideRoot(fs.root, name)
}

func (fs shareFS) Mkdir(_ context.Context, name string, perm os.FileMode) error {
	target, err := fs.resolve(name)
	if err != nil {
		return err
	}
	if target == fs.root {
		return os.ErrExist
	}
	return os.Mkdir(target, perm)
}

func (fs shareFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (xwebdav.File, error) {
	target, err := fs.resolve(name)
	if err != nil {
		return nil, err
	}
	state, conditional := ctx.Value(conditionalCreateContextKey{}).(*conditionalCreateState)
	if conditional && flag&os.O_CREATE != 0 && flag&os.O_TRUNC != 0 {
		flag |= os.O_EXCL
	}
	file, err := os.OpenFile(target, flag, perm)
	if conditional && err != nil {
		targetExists := errors.Is(err, os.ErrExist)
		if !targetExists {
			_, statErr := os.Lstat(target)
			targetExists = statErr == nil
		}
		if targetExists {
			state.targetExists.Store(true)
		}
	}
	return file, err
}

func (fs shareFS) RemoveAll(_ context.Context, name string) error {
	target, err := fs.resolve(name)
	if err != nil {
		return err
	}
	if target == fs.root {
		return os.ErrInvalid
	}
	return os.RemoveAll(target)
}

func (fs shareFS) Rename(_ context.Context, oldName, newName string) error {
	oldTarget, err := fs.resolve(oldName)
	if err != nil {
		return err
	}
	newTarget, err := fs.resolve(newName)
	if err != nil {
		return err
	}
	if oldTarget == fs.root || newTarget == fs.root {
		return os.ErrInvalid
	}
	return os.Rename(oldTarget, newTarget)
}

func (fs shareFS) Stat(_ context.Context, name string) (os.FileInfo, error) {
	target, err := fs.resolve(name)
	if err != nil {
		return nil, err
	}
	return os.Stat(target)
}
