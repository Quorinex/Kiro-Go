package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestRunServerWithDrainDrainsBeforeShutdown proves the signal->drain->shutdown
// ordering on Windows without needing to deliver a real SIGINT (which
// Windows taskkill cannot do to a detached console process). drain must run
// before shutdown(ctx) is called.
func TestRunServerWithDrainDrainsBeforeShutdown(t *testing.T) {
	signals := make(chan os.Signal, 1)
	serveStarted := make(chan struct{})
	serveDone := make(chan struct{})
	var drained atomic.Bool
	var shutdownSawDrain atomic.Bool

	serve := func() error {
		close(serveStarted)
		<-serveDone
		return http.ErrServerClosed
	}
	shutdown := func(ctx context.Context) error {
		shutdownSawDrain.Store(drained.Load())
		close(serveDone)
		return nil
	}
	drain := func() {
		drained.Store(true)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServerWithDrain(serve, shutdown, drain, signals, time.Second)
	}()

	<-serveStarted
	signals <- syscall.SIGTERM

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runServerWithDrain returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runServerWithDrain did not return")
	}
	if !drained.Load() {
		t.Fatal("expected drain to be called")
	}
	if !shutdownSawDrain.Load() {
		t.Fatal("expected shutdown to run after drain")
	}
}

// TestRunServerWithDrainNilDrainIsNoop confirms a nil drain (this repo has no
// cluster worker) does not panic and the path still shuts down cleanly.
func TestRunServerWithDrainNilDrainIsNoop(t *testing.T) {
	signals := make(chan os.Signal, 1)
	serveStarted := make(chan struct{})
	serveDone := make(chan struct{})

	serve := func() error {
		close(serveStarted)
		<-serveDone
		return http.ErrServerClosed
	}
	shutdown := func(ctx context.Context) error {
		close(serveDone)
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServerWithDrain(serve, shutdown, nil, signals, time.Second)
	}()

	<-serveStarted
	signals <- syscall.SIGINT

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runServerWithDrain returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runServerWithDrain did not return")
	}
}

// TestRunServerWithDrainReturnsWhenShutdownContextExpires confirms that if the
// in-flight serve() doesn't unblock before the shutdown deadline, the function
// returns context.DeadlineExceeded rather than hanging forever.
func TestRunServerWithDrainReturnsWhenShutdownContextExpires(t *testing.T) {
	signals := make(chan os.Signal, 1)
	serveStarted := make(chan struct{})
	serveDone := make(chan struct{})

	serve := func() error {
		close(serveStarted)
		<-serveDone
		return http.ErrServerClosed
	}
	shutdown := func(ctx context.Context) error {
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServerWithDrain(serve, shutdown, nil, signals, 20*time.Millisecond)
	}()

	<-serveStarted
	signals <- syscall.SIGTERM

	select {
	case err := <-errCh:
		close(serveDone)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected shutdown wait to end with context deadline, got %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		close(serveDone)
		t.Fatal("runServerWithDrain kept waiting for serve after shutdown context expired")
	}
}

// TestNormalizeServerShutdownError confirms http.ErrServerClosed (the normal
// result of a graceful Shutdown) is treated as success, while real errors pass through.
func TestNormalizeServerShutdownError(t *testing.T) {
	if err := normalizeServerShutdownError(nil); err != nil {
		t.Fatalf("nil should normalize to nil, got %v", err)
	}
	if err := normalizeServerShutdownError(http.ErrServerClosed); err != nil {
		t.Fatalf("ErrServerClosed should normalize to nil, got %v", err)
	}
	real := errors.New("bind: address already in use")
	if err := normalizeServerShutdownError(real); !errors.Is(err, real) {
		t.Fatalf("real error should pass through, got %v", err)
	}
}
