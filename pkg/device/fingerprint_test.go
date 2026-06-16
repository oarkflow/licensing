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

func TestGenerateFingerprintPrefersHostIdentifiersOverContainerStorage(t *testing.T) {
	hostOnly := map[string]string{
		"host_machine_id": "host-machine-abcdef1234567890abcdef1234567890",
	}
	withContainerStorage := map[string]string{
		"host_machine_id":        "host-machine-abcdef1234567890abcdef1234567890",
		"docker_volume_id":       "volume-that-should-not-win",
		"persistent_volume_id":   "pvc-that-should-not-win",
		"persistent_fallback_id": "persistent-that-should-not-win",
	}

	first, err := generateFingerprint(hostOnly)
	if err != nil {
		t.Fatalf("generateFingerprint hostOnly failed: %v", err)
	}
	second, err := generateFingerprint(withContainerStorage)
	if err != nil {
		t.Fatalf("generateFingerprint withContainerStorage failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected host identifiers to define container fingerprint, got %s then %s", first, second)
	}
}

func TestGenerateFingerprintRejectsOnlyContainerControlledStorage(t *testing.T) {
	ids := map[string]string{
		"docker_volume_id":       "volume-that-is-container-controlled",
		"persistent_volume_id":   "pvc-that-is-container-controlled",
		"persistent_fallback_id": "persistent-that-is-container-controlled",
	}

	if got, err := generateFingerprint(ids); err == nil {
		t.Fatalf("expected container-controlled storage to be rejected, got %s", got)
	}
}

func TestGenerateFingerprintRejectsPlaceholderHardwareIdentifiers(t *testing.T) {
	ids := map[string]string{
		"dmi_uuid":       "00000000-0000-0000-0000-000000000000",
		"board_serial":   "To Be Filled By O.E.M.",
		"product_serial": "default string",
		"machine_id":     "ffffffffffffffffffffffffffffffff",
	}

	if got, err := generateFingerprint(ids); err == nil {
		t.Fatalf("expected placeholder hardware identifiers to be rejected, got %s", got)
	}
}

func TestGenerateFingerprintCanonicalizesIdentifierValues(t *testing.T) {
	idsA := map[string]string{
		"dmi_uuid": " ABCDEF12-3456-7890-ABCD-EF1234567890 ",
	}
	idsB := map[string]string{
		"dmi_uuid": "abcdef12-3456-7890-abcd-ef1234567890",
	}
	first, err := generateFingerprint(idsA)
	if err != nil {
		t.Fatalf("generateFingerprint idsA failed: %v", err)
	}
	second, err := generateFingerprint(idsB)
	if err != nil {
		t.Fatalf("generateFingerprint idsB failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected canonicalized identifiers to match, got %s then %s", first, second)
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

func TestPersistentStorageFallbackDoesNotUseGenericSystemProperties(t *testing.T) {
	if got := getPersistentStorageFallback(); strings.HasPrefix(got, "system-") {
		t.Fatalf("generic system properties produced fallback identifier: %s", got)
	}
}
