package activation

import (
	"context"
	"strings"
	"testing"

	licensingclient "github.com/oarkflow/licensing/pkg/client"
)

type stubClient struct {
	activated bool
}

func (s *stubClient) ServerURL() string { return "" }

func (s *stubClient) IsActivated() bool { return s.activated }

func (s *stubClient) Verify() (*licensingclient.LicenseData, error) {
	return &licensingclient.LicenseData{}, nil
}

func TestEnvModeIsRejected(t *testing.T) {
	strategy := Strategy("env", PromptIO{})
	err := strategy.EnsureActivated(context.Background(), &stubClient{})
	if err == nil {
		t.Fatal("expected env activation mode to be rejected")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled error, got %v", err)
	}
}

func TestAutoDoesNotUseEnvironmentActivation(t *testing.T) {
	strategy := Auto(PromptIO{In: strings.NewReader(""), Out: ioDiscard{}})
	err := strategy.EnsureActivated(context.Background(), &stubClient{})
	if err == nil {
		t.Fatal("expected auto activation to fail without existing activation or prompt input")
	}
	if strings.Contains(strings.ToLower(err.Error()), "environment") {
		t.Fatalf("auto mode should not attempt environment activation, got %v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
