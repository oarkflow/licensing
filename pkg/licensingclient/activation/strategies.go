package activation

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	licensinglayer "github.com/oarflow/licensing/pkg/licensing"
	licensingclient "github.com/oarflow/licensing/pkg/licensingclient"
)

const (
	EnvActivationEmail      = "LICENSE_CLIENT_EMAIL"
	EnvActivationUsername   = "LICENSE_CLIENT_USERNAME"
	EnvActivationLicenseKey = "LICENSE_CLIENT_LICENSE_KEY"
)

// PromptIO controls where interactive prompts read from and write to.
type PromptIO struct {
	In  io.Reader
	Out io.Writer
}

// Strategy builds a composed activation strategy for the requested mode.
func Strategy(mode string, io PromptIO) licensinglayer.ActivationStrategy[*licensingclient.LicenseData] {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	switch normalized {
	case "env":
		return licensinglayer.ComposeActivation(
			licensinglayer.EnsureExistingActivation[*licensingclient.LicenseData]{},
			Env(),
		)
	case "prompt":
		return licensinglayer.ComposeActivation(
			licensinglayer.EnsureExistingActivation[*licensingclient.LicenseData]{},
			Prompt(io),
		)
	case "verify":
		return VerifyOnly()
	default:
		return Auto(io)
	}
}

// Auto ensures an existing activation, then tries env-based activation, then interactive activation.
func Auto(io PromptIO) licensinglayer.ActivationStrategy[*licensingclient.LicenseData] {
	return licensinglayer.ComposeActivation(
		licensinglayer.EnsureExistingActivation[*licensingclient.LicenseData]{},
		Env(),
		Prompt(io),
	)
}

// Env attempts activation using environment variables.
func Env() licensinglayer.ActivationStrategy[*licensingclient.LicenseData] {
	return envActivationStrategy{}
}

// Prompt collects credentials from the provided IO streams.
func Prompt(io PromptIO) licensinglayer.ActivationStrategy[*licensingclient.LicenseData] {
	return promptActivationStrategy{io: io}
}

// VerifyOnly only allows already activated clients to proceed.
func VerifyOnly() licensinglayer.ActivationStrategy[*licensingclient.LicenseData] {
	return licensinglayer.EnsureExistingActivation[*licensingclient.LicenseData]{}
}

type envActivationStrategy struct{}

func (envActivationStrategy) EnsureActivated(ctx context.Context, client licensinglayer.Client[*licensingclient.LicenseData]) error {
	typed, ok := client.(*licensingclient.Client)
	if !ok {
		return fmt.Errorf("environment activation requires *licensingclient.Client")
	}
	if typed.IsActivated() {
		return nil
	}

	email := strings.TrimSpace(os.Getenv(EnvActivationEmail))
	username := strings.TrimSpace(os.Getenv(EnvActivationUsername))
	licenseKey := strings.TrimSpace(os.Getenv(EnvActivationLicenseKey))
	if email == "" || username == "" || licenseKey == "" {
		return fmt.Errorf("environment activation not configured (set %s, %s, %s)", EnvActivationEmail, EnvActivationUsername, EnvActivationLicenseKey)
	}

	if err := typed.Activate(email, username, licenseKey); err != nil {
		return err
	}

	fmt.Fprintln(defaultWriter(nil), "\n✅ License activated via environment configuration")
	return nil
}

type promptActivationStrategy struct {
	io PromptIO
}

func (s promptActivationStrategy) EnsureActivated(ctx context.Context, client licensinglayer.Client[*licensingclient.LicenseData]) error {
	typed, ok := client.(*licensingclient.Client)
	if !ok {
		return fmt.Errorf("interactive activation requires *licensingclient.Client")
	}
	if typed.IsActivated() {
		return nil
	}

	reader := s.reader()
	writer := s.writer()

	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "⚠️  License activation required")
	fmt.Fprintln(writer)

	email, err := s.prompt(reader, writer, "Enter email: ")
	if err != nil {
		return err
	}
	username, err := s.prompt(reader, writer, "Enter username: ")
	if err != nil {
		return err
	}
	licenseKey, err := s.prompt(reader, writer, "Enter license key: ")
	if err != nil {
		return err
	}

	if err := typed.Activate(email, username, licenseKey); err != nil {
		return err
	}

	fmt.Fprintln(writer, "\n✅ License activated successfully!")
	return nil
}

func (s promptActivationStrategy) reader() *bufio.Reader {
	if reader, ok := s.io.In.(*bufio.Reader); ok && reader != nil {
		return reader
	}
	if s.io.In == nil {
		return bufio.NewReader(os.Stdin)
	}
	return bufio.NewReader(s.io.In)
}

func (s promptActivationStrategy) writer() io.Writer {
	return defaultWriter(s.io.Out)
}

func (s promptActivationStrategy) prompt(reader *bufio.Reader, writer io.Writer, label string) (string, error) {
	fmt.Fprint(writer, label)
	text, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if errors.Is(err, io.EOF) && !strings.HasSuffix(text, "\n") {
		fmt.Fprintln(writer)
	}
	value := strings.TrimSpace(text)
	if value == "" {
		return "", fmt.Errorf("%s is required", strings.TrimSuffix(label, ": "))
	}
	return value, nil
}

func defaultWriter(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stdout
}
