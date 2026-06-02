package device

import (
	"strings"
	"testing"
)

func TestGenerateFingerprintIsVersionedAndDeterministic(t *testing.T) {
	idsA := map[string]string{
		"machine_id":   "machine-12345678901234567890123456789012",
		"dmi_uuid":     "dmi-12345678901234567890123456789012",
		"board_serial": "board-1234567890",
		"container_id": "ephemeral-container",
	}
	idsB := map[string]string{
		"container_id": "ephemeral-container",
		"board_serial": "board-1234567890",
		"dmi_uuid":     "dmi-12345678901234567890123456789012",
		"machine_id":   "machine-12345678901234567890123456789012",
	}
	first, err := generateFingerprint(idsA)
	if err != nil {
		t.Fatalf("generateFingerprint first failed: %v", err)
	}
	second, err := generateFingerprint(idsB)
	if err != nil {
		t.Fatalf("generateFingerprint second failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected deterministic fingerprint independent of map order, got %s then %s", first, second)
	}
	if !strings.HasPrefix(first, "hw:v1:") {
		t.Fatalf("expected versioned hardware fingerprint, got %s", first)
	}
}

func TestGenerateFingerprintIgnoresLowConfidenceWhenStableExists(t *testing.T) {
	stable := map[string]string{
		"dmi_uuid":   "dmi-abcdef1234567890abcdef1234567890",
		"machine_id": "machine-abcdef1234567890abcdef1234567890",
	}
	withEphemeral := map[string]string{
		"dmi_uuid":     "dmi-abcdef1234567890abcdef1234567890",
		"machine_id":   "machine-abcdef1234567890abcdef1234567890",
		"container_id": "container-that-must-not-bind",
		"pod_uid":      "pod-that-must-not-bind",
	}
	first, err := generateFingerprint(stable)
	if err != nil {
		t.Fatalf("generateFingerprint stable failed: %v", err)
	}
	second, err := generateFingerprint(withEphemeral)
	if err != nil {
		t.Fatalf("generateFingerprint with ephemeral failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected low-confidence identifiers to be ignored when stable IDs exist, got %s then %s", first, second)
	}
}

func TestConfiguredDeviceIDClassificationIsHighConfidence(t *testing.T) {
	if priority := getIdentifierPriority("configured_device_id"); priority < 8 {
		t.Fatalf("expected configured_device_id to have high priority, got %d", priority)
	}
	if confidence := getIdentifierConfidence("configured_device_id"); confidence != "high" {
		t.Fatalf("expected configured_device_id high confidence, got %s", confidence)
	}
}

func TestKubernetesPVCIDDoesNotFallbackToPodName(t *testing.T) {
	t.Setenv("POD_NAME", "ephemeral-pod")
	t.Setenv("POD_NAMESPACE", "default")
	t.Setenv("HOSTNAME", "ephemeral-host")
	t.Setenv("POD_UID", "ephemeral-uid")
	if got := getKubernetesPVCID(); got != "" {
		t.Fatalf("expected no PVC ID from pod-only metadata, got %s", got)
	}
}

func TestEnvironmentVariablesDoNotCreateHardwareIdentifiers(t *testing.T) {
	t.Setenv("DEVICE_ID", "stable-device-123")
	t.Setenv("LICENSE_DEVICE_ID", "stable-license-device")
	t.Setenv("DOCKER_VOLUME_ID", "volume-from-env")
	t.Setenv("VOLUME_ID", "volume-from-env")
	t.Setenv("PVC_NAME", "pvc-from-env")
	t.Setenv("POD_NAMESPACE", "default")

	if got := getDockerVolumeID(); strings.HasPrefix(got, "env-") {
		t.Fatalf("environment variable produced docker volume id: %s", got)
	}
	if got := getKubernetesPVCID(); strings.HasPrefix(got, "k8s-env-") || strings.Contains(got, "pvc-from-env") {
		t.Fatalf("environment variable produced kubernetes pvc id: %s", got)
	}
}
