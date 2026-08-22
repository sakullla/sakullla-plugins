package sdklock

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestVerificationCacheLockWaitsForPublisher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verification.lock")
	publisher, err := acquireVerificationCacheLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		lock *verificationCacheLock
		err  error
	}
	waiter := make(chan result, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		lock, err := acquireVerificationCacheLock(context.Background(), path)
		waiter <- result{lock: lock, err: err}
	}()
	<-started
	select {
	case got := <-waiter:
		if got.lock != nil {
			got.lock.Close()
		}
		t.Fatalf("waiter completed while publisher held the lock: %v", got.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := publisher.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-waiter:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if err := got.lock.Close(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not acquire the published cache lock")
	}
}

func TestVerificationCacheLockHonorsCallerDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verification.lock")
	publisher, err := acquireVerificationCacheLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	lock, err := acquireVerificationCacheLock(ctx, path)
	if lock != nil {
		lock.Close()
		t.Fatal("deadline-bound waiter acquired a held cache lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait error = %v, want context deadline exceeded", err)
	}
}
