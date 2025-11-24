package runner

import (
	"context"
	"fmt"
	"log"
)

// Client describes the minimal capabilities required by the licensing runner.
type Client[T any] interface {
	ServerURL() string
	IsActivated() bool
	Verify() (T, error)
}

// ClientFactory builds a client instance on demand.
type ClientFactory[T any] func() (Client[T], error)

// LicensedAppFunc represents the entrypoint for the protected application.
type LicensedAppFunc[T any] func(context.Context, T) error

// ActivationStrategy allows applications to customize how initial activation happens.
type ActivationStrategy[T any] interface {
	EnsureActivated(context.Context, Client[T]) error
}

// ActivationFunc adapts a simple function into an ActivationStrategy.
type ActivationFunc[T any] func(context.Context, Client[T]) error

// EnsureActivated implements ActivationStrategy for ActivationFunc.
func (f ActivationFunc[T]) EnsureActivated(ctx context.Context, client Client[T]) error {
	if f == nil {
		return nil
	}
	return f(ctx, client)
}

// EnsureExistingActivation validates that the client already holds an activation.
type EnsureExistingActivation[T any] struct{}

// EnsureActivated implements ActivationStrategy.
func (EnsureExistingActivation[T]) EnsureActivated(_ context.Context, client Client[T]) error {
	if client.IsActivated() {
		return nil
	}
	return fmt.Errorf("license is not activated on this device")
}

// ActivationChain composes multiple ActivationStrategy instances in order.
type ActivationChain[T any] []ActivationStrategy[T]

// EnsureActivated executes strategies in order until one succeeds.
func (chain ActivationChain[T]) EnsureActivated(ctx context.Context, client Client[T]) error {
	if len(chain) == 0 {
		return nil
	}
	var lastErr error
	for _, strategy := range chain {
		if strategy == nil {
			continue
		}
		if err := strategy.EnsureActivated(ctx, client); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// ComposeActivation helper to build an ActivationChain.
func ComposeActivation[T any](strategies ...ActivationStrategy[T]) ActivationStrategy[T] {
	return ActivationChain[T](strategies)
}

// Logger captures the subset of log.Logger used by the runner.
type Logger interface {
	Printf(format string, args ...interface{})
}

// Hooks allow callers to integrate additional behavior around verification.
type Hooks[T any] struct {
	BeforeVerify func(context.Context, Client[T]) error
	AfterVerify  func(context.Context, T) error
}

// Config holds runner configuration knobs.
type Config[T any] struct {
	ClientFactory ClientFactory[T]
	Activation    ActivationStrategy[T]
	Hooks         Hooks[T]
	Logger        Logger
}

// Runner wraps application execution with licensing guarantees.
type Runner[T any] struct {
	cfg Config[T]
}

// NewRunner constructs a Runner with validation.
func NewRunner[T any](cfg Config[T]) (*Runner[T], error) {
	if cfg.ClientFactory == nil {
		return nil, fmt.Errorf("ClientFactory is required")
	}
	return &Runner[T]{cfg: cfg}, nil
}

// Run performs activation, verification, and executes the protected app.
func (r *Runner[T]) Run(ctx context.Context, fn LicensedAppFunc[T]) error {
	if fn == nil {
		return fmt.Errorf("licensed application entrypoint is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	client, err := r.cfg.ClientFactory()
	if err != nil {
		return fmt.Errorf("failed to initialize license client: %w", err)
	}

	logger := r.cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	activation := r.cfg.Activation
	if activation == nil {
		activation = EnsureExistingActivation[T]{}
	}
	if err := activation.EnsureActivated(ctx, client); err != nil {
		return fmt.Errorf("activation failed: %w", err)
	}

	if hook := r.cfg.Hooks.BeforeVerify; hook != nil {
		if err := hook(ctx, client); err != nil {
			return fmt.Errorf("before verify hook failed: %w", err)
		}
	}

	license, err := client.Verify()
	if err != nil {
		return fmt.Errorf("license verification failed: %w", err)
	}
	if hook := r.cfg.Hooks.AfterVerify; hook != nil {
		if err := hook(ctx, license); err != nil {
			return fmt.Errorf("after verify hook failed: %w", err)
		}
	}

	return fn(ctx, license)
}
