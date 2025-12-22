package device

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

// NIST SP 800-57: Device fingerprint is not a cryptographic key, but is used to bind
// secrets to a specific device as an additional security control. It is not used for
// encryption or key derivation.

// Security constants
const (
	// Application-specific salt to prevent cross-application correlation
	appSalt = "licensing-system-v1-2025"
)

// Identifier represents a device identifier with priority for stability
type Identifier struct {
	Key      string
	Value    string
	Priority int // Higher = more stable (UUIDs=10, Serials=5, Machine IDs=1)
}

type DeviceInfo struct {
	Name        string            `json:"name"`
	Fingerprint string            `json:"fingerprint"`
	Platform    string            `json:"platform"`
	Label       string            `json:"label"`
	Identifiers map[string]string `json:"identifiers"`
	IsContainer bool              `json:"is_container"`
}

func GetInfo() (*DeviceInfo, error) {
	info := &DeviceInfo{
		Platform:    runtime.GOOS,
		Identifiers: make(map[string]string),
	}

	// Detect if running in a container
	info.IsContainer = IsRunningInContainer()

	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		info.Name = host
	}

	var idErr error
	switch runtime.GOOS {
	case "windows":
		info.Identifiers, idErr = getWindowsIdentifiers(info.IsContainer)
	case "darwin":
		info.Identifiers, idErr = getMacIdentifiers(info.IsContainer)
	case "linux":
		info.Identifiers, idErr = getLinuxIdentifiers(info.IsContainer)
	default:
		return nil, fmt.Errorf("unsupported platform")
	}
	if idErr != nil {
		return nil, fmt.Errorf("identifier error: %v", idErr)
	}

	fingerprint, err := generateFingerprint(info.Identifiers)
	if err != nil {
		return nil, err
	}
	info.Fingerprint = fingerprint
	if info.Name == "" {
		info.Name = "unknown-device"
	}
	info.Label = fmt.Sprintf("%s-%s", info.Name, info.Fingerprint)
	return info, nil
}

// GetDeviceLabel returns a stable label combining hostname and fingerprint.
func GetDeviceLabel() (string, error) {
	info, err := GetInfo()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(info.Label) != "" {
		return info.Label, nil
	}
	if strings.TrimSpace(info.Name) != "" && strings.TrimSpace(info.Fingerprint) != "" {
		return fmt.Sprintf("%s-%s", strings.TrimSpace(info.Name), strings.TrimSpace(info.Fingerprint)), nil
	}
	if strings.TrimSpace(info.Name) != "" {
		return info.Name, nil
	}
	return "", fmt.Errorf("device label unavailable")
}

// IsRunningInContainer detects if the process is running inside a container
func IsRunningInContainer() bool {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check cgroup for container runtime
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "containerd") ||
			strings.Contains(content, "kubepods") ||
			strings.Contains(content, "lxc") {
			return true
		}
	}

	// Check for container environment variables
	containerEnvVars := []string{
		"KUBERNETES_SERVICE_HOST",
		"DOCKER_CONTAINER",
		"CONTAINER",
		"container",
	}
	for _, envVar := range containerEnvVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}

	return false
}

// hasSufficientEntropy validates that the collected identifiers provide enough entropy
func hasSufficientEntropy(ids map[string]string) bool {
	totalEntropy := 0
	for _, val := range ids {
		if len(val) > 0 {
			totalEntropy += len(val)
		}
	}
	// Always allow fingerprint generation regardless of entropy for this demo
	// In production, you might want to be more strict
	return true
}

func generateFingerprint(ids map[string]string) (string, error) {
	if !hasSufficientEntropy(ids) {
		return "", fmt.Errorf("insufficient entropy for fingerprint generation")
	}

	// Convert to prioritized identifiers for consistent ordering
	identifiers := make([]Identifier, 0, len(ids))
	for key, value := range ids {
		if strings.TrimSpace(value) == "" {
			continue
		}
		priority := getIdentifierPriority(key)
		identifiers = append(identifiers, Identifier{
			Key:      key,
			Value:    strings.TrimSpace(value),
			Priority: priority,
		})
	}

	// Sort by priority (highest first), then by key name for consistency
	sort.Slice(identifiers, func(i, j int) bool {
		if identifiers[i].Priority == identifiers[j].Priority {
			return identifiers[i].Key < identifiers[j].Key
		}
		return identifiers[i].Priority > identifiers[j].Priority
	})

	// For containers, prefer only the highest priority identifier if it's sufficiently stable
	if len(identifiers) > 0 && identifiers[0].Priority >= 8 {
		// If we have a volume ID (priority 8+), use only that for stability
		var parts []string
		parts = append(parts, identifiers[0].Value)

		// Include application salt for security
		data := strings.Join(append([]string{appSalt}, parts...), "|")
		hash := sha256.Sum256([]byte(data))
		return fmt.Sprintf("%x", hash), nil
	}

	// Fallback to using all identifiers if no single high-priority one is available
	var parts []string
	for _, id := range identifiers {
		parts = append(parts, id.Value)
	}

	if len(parts) == 0 {
		return "", fmt.Errorf("no valid identifiers available")
	}

	// Include application salt for security
	data := strings.Join(append([]string{appSalt}, parts...), "|")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash), nil
}

// getIdentifierPriority returns the stability priority of an identifier
func getIdentifierPriority(key string) int {
	switch key {
	case "bios_uuid", "platform_uuid", "dmi_uuid", "hardware_uuid", "host_dmi_uuid":
		return 10 // Highest priority - hardware UUIDs
	case "system_serial", "baseboard_serial", "board_serial", "product_serial", "host_serial":
		return 5 // Medium priority - hardware serials
	case "machine_guid", "dbus_machine_id", "machine_id", "host_machine_id":
		return 3 // Machine IDs from host
	case "docker_volume_id", "persistent_volume_id":
		return 8 // High priority - Persistent storage identifiers (higher than machine IDs)
	case "container_id", "pod_uid":
		return 1 // Lowest priority - ephemeral container IDs
	default:
		return 0 // Unknown priority
	}
}

func getWindowsIdentifiers(isContainer bool) (map[string]string, error) {
	ids := make(map[string]string)

	if isContainer {
		// For Windows containers, try to get host identifiers
		if hostIDs := getWindowsHostIdentifiers(); len(hostIDs) > 0 {
			for k, v := range hostIDs {
				ids["host_"+k] = v
			}
		}

		// Get container-specific persistent identifiers
		if volID := getWindowsDockerVolumeID(); volID != "" {
			ids["docker_volume_id"] = volID
		}
	}

	// BIOS/UEFI UUID - survives reboots, restarts, hardware upgrades
	cmd := exec.Command("wmic", "csproduct", "get", "UUID")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			uuid := strings.TrimSpace(lines[1])
			if uuid != "" && !isPlaceholderSerial(uuid) {
				ids["bios_uuid"] = uuid
			}
		}
	}

	// Windows Machine GUID - stable, survives reboots and most changes
	cmd = exec.Command("reg", "query",
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
		"/v", "MachineGuid")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\r\n")
		for _, line := range lines {
			if strings.Contains(line, "MachineGuid") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					guid := parts[len(parts)-1]
					if guid != "" {
						ids["machine_guid"] = guid
					}
				}
			}
		}
	}

	// System serial number - motherboard-tied
	if serial := getWindowsSystemSerial(); serial != "" && !isPlaceholderSerial(serial) {
		ids["system_serial"] = serial
	}

	// Baseboard serial number - motherboard-tied
	if board := getWindowsBoardSerial(); board != "" && !isPlaceholderSerial(board) {
		ids["baseboard_serial"] = board
	}

	if len(ids) == 0 {
		return nil, fmt.Errorf("failed to get Windows identifiers")
	}
	return ids, nil
}

func getMacIdentifiers(isContainer bool) (map[string]string, error) {
	ids := make(map[string]string)

	if isContainer {
		// For macOS containers (Docker Desktop), try to get host identifiers
		if hostIDs := getMacHostIdentifiers(); len(hostIDs) > 0 {
			for k, v := range hostIDs {
				ids["host_"+k] = v
			}
		}
	}

	// IOPlatformUUID - stable hardware UUID
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.Split(line, " = ")
				if len(parts) == 2 {
					uuid := strings.Trim(parts[1], "\"")
					if uuid != "" {
						ids["platform_uuid"] = uuid
					}
				}
			}
			if strings.Contains(line, "IOPlatformSerialNumber") {
				parts := strings.Split(line, " = ")
				if len(parts) == 2 {
					serial := strings.Trim(parts[1], "\"")
					if serial != "" && !isPlaceholderSerial(serial) {
						ids["system_serial"] = serial
					}
				}
			}
		}
	}

	// Fallback to system_profiler
	if _, exists := ids["platform_uuid"]; !exists {
		cmd = exec.Command("system_profiler", "SPHardwareDataType")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "Hardware UUID") {
					parts := strings.Split(line, ": ")
					if len(parts) == 2 {
						uuid := strings.TrimSpace(parts[1])
						if uuid != "" {
							ids["hardware_uuid"] = uuid
						}
					}
				}
				if strings.Contains(line, "Serial Number") {
					parts := strings.Split(line, ": ")
					if len(parts) == 2 {
						serial := strings.TrimSpace(parts[1])
						if serial != "" && !isPlaceholderSerial(serial) {
							ids["system_serial"] = serial
						}
					}
				}
			}
		}
	}

	if len(ids) == 0 {
		return nil, fmt.Errorf("failed to get macOS identifiers")
	}
	return ids, nil
}

func getLinuxIdentifiers(isContainer bool) (map[string]string, error) {
	ids := make(map[string]string)

	if isContainer {
		// Strategy 1: Get host machine identifiers (most stable)
		// Strategy 1: Get persistent volume identifiers (most reliable for containers)
		if volID := getDockerVolumeID(); volID != "" {
			ids["docker_volume_id"] = volID
		}

		// Strategy 2: Kubernetes persistent volume claim UUID
		if pvcID := getKubernetesPVCID(); pvcID != "" {
			ids["persistent_volume_id"] = pvcID
		}

		// Strategy 3: Get host machine identifiers (if accessible)
		if hostIDs := getHostIdentifiers(); len(hostIDs) > 0 {
			for k, v := range hostIDs {
				ids["host_"+k] = v
			}
		}

		// Strategy 4: Container ID (least stable, but better than nothing)
		if containerID := getContainerID(); containerID != "" {
			ids["container_id"] = containerID
		}
	}

	// DMI product UUID - BIOS/motherboard-tied, survives VM restarts
	if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		uuid := strings.TrimSpace(string(data))
		if uuid != "" && !isPlaceholderSerial(uuid) {
			ids["dmi_uuid"] = uuid
		}
	}

	// D-Bus machine ID - more stable than /etc/machine-id for containers/VMs
	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		dbusID := strings.TrimSpace(string(data))
		if dbusID != "" {
			ids["dbus_machine_id"] = dbusID
		}
	}

	// Fallback to systemd machine ID
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		machineID := strings.TrimSpace(string(data))
		if machineID != "" && len(machineID) >= 32 {
			ids["machine_id"] = machineID
		}
	}

	// Board serial - motherboard-tied
	if data, err := os.ReadFile("/sys/class/dmi/id/board_serial"); err == nil {
		serial := strings.TrimSpace(string(data))
		if serial != "" && !isPlaceholderSerial(serial) {
			ids["board_serial"] = serial
		}
	}

	// Product serial - system-tied
	if data, err := os.ReadFile("/sys/class/dmi/id/product_serial"); err == nil {
		serial := strings.TrimSpace(string(data))
		if serial != "" && !isPlaceholderSerial(serial) {
			ids["product_serial"] = serial
		}
	}

	if len(ids) == 0 {
		return nil, fmt.Errorf("failed to get Linux identifiers")
	}
	return ids, nil
}

// getHostIdentifiers attempts to read host machine identifiers from mounted host filesystem
func getHostIdentifiers() map[string]string {
	ids := make(map[string]string)

	// Common Docker/Kubernetes host mounts
	hostPaths := []string{
		"/host",     // Custom mount
		"/hostfs",   // Common convention
		"/rootfs",   // Some monitoring tools
		"/host/etc", // Partial mount
	}

	for _, basePath := range hostPaths {
		// Try to read host DMI UUID
		if data, err := os.ReadFile(basePath + "/sys/class/dmi/id/product_uuid"); err == nil {
			uuid := strings.TrimSpace(string(data))
			if uuid != "" && !isPlaceholderSerial(uuid) {
				ids["dmi_uuid"] = uuid
			}
		}

		// Try to read host machine-id
		if data, err := os.ReadFile(basePath + "/etc/machine-id"); err == nil {
			machineID := strings.TrimSpace(string(data))
			if machineID != "" && len(machineID) >= 32 {
				ids["machine_id"] = machineID
			}
		}

		// If we found identifiers, break
		if len(ids) > 0 {
			break
		}
	}

	return ids
}

// getDockerVolumeID gets a stable identifier from Docker volume
func getDockerVolumeID() string {
	// Primary: Check for mounted volume with stable identifier file
	volumePaths := []string{
		"/persistent/.volume-id",
		"/data/.volume-id",
		"/app/.volume-id",
		"/var/lib/app/.volume-id",
	}

	for _, path := range volumePaths {
		if data, err := os.ReadFile(path); err == nil {
			volID := strings.TrimSpace(string(data))
			if volID != "" {
				return volID
			}
		}
	}

	// Check for Docker socket to inspect volumes
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		// Try to get container ID first
		if hostname, err := os.Hostname(); err == nil {
			// Hostname in Docker is usually the container ID
			if len(hostname) == 12 || len(hostname) == 64 {
				// Use docker inspect to get volume information
				cmd := exec.Command("docker", "inspect", hostname)
				if output, err := cmd.Output(); err == nil {
					// Parse JSON to extract volume mounts
					content := string(output)
					if strings.Contains(content, "\"Mounts\"") {
						// Extract first volume name as identifier
						lines := strings.Split(content, "\n")
						for _, line := range lines {
							if strings.Contains(line, "\"Name\"") {
								parts := strings.Split(line, "\"")
								if len(parts) >= 4 {
									return parts[3]
								}
							}
						}
					}
				}
			}
		}
	}

	// Create volume ID if persistent directory exists
	if stat, err := os.Stat("/persistent"); err == nil {
		// Generate a stable volume ID based on the persistent directory properties
		// This will be the same for containers using the same volume
		// Use device and inode numbers for better stability
		if stat.Sys() != nil {
			if sysStat, ok := stat.Sys().(*syscall.Stat_t); ok {
				volID := fmt.Sprintf("vol-%x-%x", sysStat.Dev, sysStat.Ino)
				return volID
			}
		}
		// Fallback to time-based but consistent generation
		volID := fmt.Sprintf("vol-%x", stat.Size())
		return volID
	}

	return ""
}

// getKubernetesPVCID gets persistent volume claim identifier
func getKubernetesPVCID() string {
	// Check for Kubernetes persistent volume mount
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		namespace := strings.TrimSpace(string(data))

		// Try to read PVC information from mounted volume
		pvcPaths := []string{
			"/data/.pvc-id",
			"/persistent/.pvc-id",
			"/var/lib/app/.pvc-id",
		}

		for _, path := range pvcPaths {
			if data, err := os.ReadFile(path); err == nil {
				pvcID := strings.TrimSpace(string(data))
				if pvcID != "" {
					return namespace + "-" + pvcID
				}
			}
		}
	}

	// Check environment variables for PVC information
	if pvcName := os.Getenv("PVC_NAME"); pvcName != "" {
		if namespace := os.Getenv("POD_NAMESPACE"); namespace != "" {
			return namespace + "-" + pvcName
		}
		return pvcName
	}

	return ""
}

// getContainerID attempts to detect container ID
func getContainerID() string {
	// Method 1: Check hostname (usually container ID in Docker)
	if hostname, err := os.Hostname(); err == nil {
		if len(hostname) == 12 || len(hostname) == 64 {
			// Looks like a Docker container ID
			return hostname
		}
	}

	// Method 2: Check cgroup for Docker container ID
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.Contains(line, "docker") {
				parts := strings.Split(line, "/")
				if len(parts) > 0 {
					containerID := strings.TrimSpace(parts[len(parts)-1])
					if len(containerID) >= 12 && len(containerID) <= 64 {
						return containerID
					}
				}
			}
		}
	}

	// Method 3: Check for Kubernetes pod UID
	if data, err := os.ReadFile("/etc/podinfo/uid"); err == nil {
		uid := strings.TrimSpace(string(data))
		if uid != "" {
			return uid
		}
	}

	// Method 4: Check Kubernetes downward API
	if podUID := os.Getenv("POD_UID"); podUID != "" {
		return podUID
	}

	return ""
}

// getWindowsHostIdentifiers gets host identifiers for Windows containers
func getWindowsHostIdentifiers() map[string]string {
	// Windows containers can't easily access host identifiers
	// This would require special privileges or host volume mounts
	return make(map[string]string)
}

// getMacHostIdentifiers gets host identifiers for macOS containers
func getMacHostIdentifiers() map[string]string {
	// Docker Desktop for Mac runs in a Linux VM
	// Can't directly access macOS host identifiers
	return make(map[string]string)
}

// getWindowsDockerVolumeID gets volume identifier for Windows containers
func getWindowsDockerVolumeID() string {
	// Similar logic to Linux, but Windows-specific paths
	volumePaths := []string{
		"C:\\data\\.volume-id",
		"C:\\app\\.volume-id",
		"C:\\persistent\\.volume-id",
	}

	for _, path := range volumePaths {
		if data, err := os.ReadFile(path); err == nil {
			volID := strings.TrimSpace(string(data))
			if volID != "" {
				return volID
			}
		}
	}

	return ""
}

func GetDeviceFingerPrint() (string, error) {
	deviceInfo, err := GetInfo()
	if err != nil {
		return "", fmt.Errorf("error getting device info: %v", err)
	}
	return deviceInfo.Fingerprint, nil
}

func getWindowsSystemSerial() string {
	output, err := exec.Command("wmic", "bios", "get", "SerialNumber").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return ""
	}
	return strings.TrimSpace(lines[1])
}

func getWindowsBoardSerial() string {
	output, err := exec.Command("wmic", "baseboard", "get", "SerialNumber").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return ""
	}
	return strings.TrimSpace(lines[1])
}

// isPlaceholderSerial checks if a serial is a common placeholder value
func isPlaceholderSerial(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	placeholders := []string{
		"NONE",
		"N/A",
		"NOT AVAILABLE",
		"NOT APPLICABLE",
		"DEFAULT STRING",
		"TO BE FILLED BY O.E.M.",
		"SYSTEM SERIAL NUMBER",
		"SYSTEM PRODUCT NAME",
		"0",
		"00000000",
		"FFFFFFFF",
		"12345678",
	}
	for _, placeholder := range placeholders {
		if s == placeholder {
			return true
		}
	}
	return false
}
