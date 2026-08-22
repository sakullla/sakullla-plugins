package webdav

import (
	"context"
	"os"

	xwebdav "golang.org/x/net/webdav"
)

type shareFS struct {
	root string
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

func (fs shareFS) OpenFile(_ context.Context, name string, flag int, perm os.FileMode) (xwebdav.File, error) {
	target, err := fs.resolve(name)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(target, flag, perm)
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
