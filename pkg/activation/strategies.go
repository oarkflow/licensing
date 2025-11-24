package activation

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	licensingclient "github.com/oarflow/licensing/pkg/client"
	"github.com/oarflow/licensing/pkg/runner"
)

const (
	EnvActivationEmail      = "LICENSE_CLIENT_EMAIL"
	EnvActivationClientID   = "LICENSE_CLIENT_ID"
	EnvActivationLicenseKey = "LICENSE_CLIENT_LICENSE_KEY"
)

var licenseFilePath string

type licenseFileData struct {
	Email      string `json:"email"`
	ClientID   string `json:"client_id"`
	LicenseKey string `json:"license_key"`
}

// SetLicenseFilePath configures the optional JSON file used to pre-fill activation prompts.
func SetLicenseFilePath(path string) {
	licenseFilePath = strings.TrimSpace(path)
}

func loadLicenseFileData() (*licenseFileData, error) {
	if licenseFilePath == "" {
		return nil, nil
	}
	contents, err := os.ReadFile(licenseFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file %q: %w", licenseFilePath, err)
	}
	var data licenseFileData
	if err := json.Unmarshal(contents, &data); err != nil {
		return nil, fmt.Errorf("failed to parse license file %q: %w", licenseFilePath, err)
	}
	return &data, nil
}

// PromptIO controls where interactive prompts read from and write to.
type PromptIO struct {
	In  io.Reader
	Out io.Writer
}

// Strategy builds a composed activation strategy for the requested mode.
func Strategy(mode string, io PromptIO) runner.ActivationStrategy[*licensingclient.LicenseData] {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "env":
		return Env()
	case "prompt":
		return Prompt(io)
	case "verify":
		return VerifyOnly()
	case "auto", "":
		return Auto(io)
	default:
		return Auto(io)
	}
}

// Auto ensures an existing activation, then tries env-based activation, then interactive activation.
func Auto(io PromptIO) runner.ActivationStrategy[*licensingclient.LicenseData] {
	return runner.ComposeActivation(
		runner.EnsureExistingActivation[*licensingclient.LicenseData]{},
		Env(),
		Prompt(io),
	)
}

// Env attempts activation using environment variables.
func Env() runner.ActivationStrategy[*licensingclient.LicenseData] {
	return envActivationStrategy{}
}

// Prompt collects credentials from the provided IO streams.
func Prompt(io PromptIO) runner.ActivationStrategy[*licensingclient.LicenseData] {
	return promptActivationStrategy{io: io}
}

// VerifyOnly only allows already activated clients to proceed.
func VerifyOnly() runner.ActivationStrategy[*licensingclient.LicenseData] {
	return runner.EnsureExistingActivation[*licensingclient.LicenseData]{}
}

type envActivationStrategy struct{}

func (envActivationStrategy) EnsureActivated(ctx context.Context, client runner.Client[*licensingclient.LicenseData]) error {
	typed, ok := client.(*licensingclient.Client)
	if !ok {
		return fmt.Errorf("environment activation requires *licensingclient.Client")
	}
	if typed.IsActivated() {
		return nil
	}

	email := strings.TrimSpace(os.Getenv(EnvActivationEmail))
	licenseKey := strings.TrimSpace(os.Getenv(EnvActivationLicenseKey))
	clientID := strings.TrimSpace(os.Getenv(EnvActivationClientID))
	if email == "" || licenseKey == "" {
		return fmt.Errorf("environment activation not configured (set %s and %s)", EnvActivationEmail, EnvActivationLicenseKey)
	}
	if clientID == "" {
		return fmt.Errorf("environment activation requires %s", EnvActivationClientID)
	}

	if err := typed.Activate(email, clientID, licenseKey); err != nil {
		return err
	}

	fmt.Fprintln(defaultWriter(nil), "\n✅ License activated via environment configuration")
	return nil
}

type promptActivationStrategy struct {
	io PromptIO
}

func (s promptActivationStrategy) EnsureActivated(ctx context.Context, client runner.Client[*licensingclient.LicenseData]) error {
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

	preset, err := loadLicenseFileData()
	if err != nil {
		return err
	}
	email := ""
	clientID := ""
	licenseKey := ""
	if preset != nil {
		email = strings.TrimSpace(preset.Email)
		clientID = strings.TrimSpace(preset.ClientID)
		licenseKey = strings.TrimSpace(preset.LicenseKey)
	}
	if email == "" {
		email, err = s.prompt(reader, writer, "Enter email: ")
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintf(writer, "Using email from license file: %s\n", email)
	}
	if licenseKey == "" {
		licenseKey, err = s.prompt(reader, writer, "Enter license key: ")
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintln(writer, "Using license key from license file")
	}
	if clientID == "" {
		clientID, err = s.prompt(reader, writer, "Enter client ID: ")
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintf(writer, "Using client ID from license file: %s\n", clientID)
	}

	if err := typed.Activate(email, clientID, licenseKey); err != nil {
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

func (s promptActivationStrategy) promptOptional(reader *bufio.Reader, writer io.Writer, label string) (string, error) {
	fmt.Fprint(writer, label)
	text, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if errors.Is(err, io.EOF) && !strings.HasSuffix(text, "\n") {
		fmt.Fprintln(writer)
	}
	return strings.TrimSpace(text), nil
}

func defaultWriter(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stdout
}
