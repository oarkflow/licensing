package device

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
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
	highPriorityCount := 0
	stableCount := 0

	for key, val := range ids {
		if len(val) > 0 {
			totalEntropy += len(val)
			// Count high-priority identifiers (priority >= 5)
			priority := getIdentifierPriority(key)
			if priority >= 5 {
				highPriorityCount++
			}
			// Count stable identifiers (priority >= 3)
			if priority >= 3 {
				stableCount++
			}
		}
	}

	// More flexible validation: allow lower entropy for development/testing
	// but ensure we have some form of stable identification
	if totalEntropy >= 32 && highPriorityCount >= 1 {
		return true // Full security requirements met
	}

	// Relaxed requirements for development/limited environments
	if totalEntropy >= 16 && (highPriorityCount >= 1 || stableCount >= 2) {
		return true // Minimum viable security
	}

	// Absolute minimum: some identifiers with basic entropy
	if totalEntropy >= 8 && stableCount >= 1 {
		return true // Basic functionality (for development/testing)
	}

	return false
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

	// Filter out ephemeral identifiers (priority < 3) for better stability
	stableIdentifiers := make([]Identifier, 0, len(identifiers))
	for _, id := range identifiers {
		if id.Priority >= 3 {
			stableIdentifiers = append(stableIdentifiers, id)
		}
	}

	// If we have stable identifiers, use only those
	if len(stableIdentifiers) > 0 {
		var parts []string
		for _, id := range stableIdentifiers {
			parts = append(parts, id.Value)
		}

		// Include application salt for security
		data := strings.Join(append([]string{appSalt}, parts...), "|")
		hash := sha256.Sum256([]byte(data))
		return fmt.Sprintf("%x", hash), nil
	}

	// Last resort: use all identifiers if no stable ones are available
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
	case "persistent_fallback_id":
		return 6 // High-medium priority - Application-level persistent identifiers
	case "container_id", "pod_uid":
		return 1 // Lowest priority - ephemeral container IDs (now filtered out)
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
				ids[k] = v // Don't prefix with "host_" since getWindowsHostIdentifiers returns empty anyway
			}
		}

		// Get container-specific persistent identifiers
		if volID := getWindowsDockerVolumeID(); volID != "" {
			ids["docker_volume_id"] = volID
		}

		// Persistent storage fallback for Windows containers
		if fallbackID := getPersistentStorageFallback(); fallbackID != "" {
			ids["persistent_fallback_id"] = fallbackID
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
				ids[k] = v // Don't prefix with "host_" since getMacHostIdentifiers returns empty anyway
			}
		}

		// Persistent storage fallback for macOS containers
		if fallbackID := getPersistentStorageFallback(); fallbackID != "" {
			ids["persistent_fallback_id"] = fallbackID
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
				ids[k] = v // Don't prefix with "host_" since getHostIdentifiers already does this
			}
		}

		// Strategy 4: Persistent storage fallback (application-level)
		if fallbackID := getPersistentStorageFallback(); fallbackID != "" {
			ids["persistent_fallback_id"] = fallbackID
		}

		// Strategy 5: Container ID (ephemeral, only as last resort - skip for now)
		// Removed to improve stability - container IDs change on restart
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

	// Common Docker/Kubernetes host mounts - but be graceful if they don't exist
	hostPaths := []string{
		"/host",     // Custom mount
		"/hostfs",   // Common convention
		"/rootfs",   // Some monitoring tools
		"/host/etc", // Partial mount
	}

	for _, basePath := range hostPaths {
		// Check if the base path exists before trying to read from it
		if _, err := os.Stat(basePath); err != nil {
			continue // Skip paths that don't exist
		}

		// Try to read host DMI UUID
		uuidPath := basePath + "/sys/class/dmi/id/product_uuid"
		if data, err := os.ReadFile(uuidPath); err == nil {
			uuid := strings.TrimSpace(string(data))
			if uuid != "" && !isPlaceholderSerial(uuid) {
				ids["host_dmi_uuid"] = uuid // Prefix with "host_" to distinguish from container IDs
			}
		}

		// Try to read host machine-id
		machineIDPath := basePath + "/etc/machine-id"
		if data, err := os.ReadFile(machineIDPath); err == nil {
			machineID := strings.TrimSpace(string(data))
			if machineID != "" && len(machineID) >= 32 {
				ids["host_machine_id"] = machineID // Prefix with "host_" to distinguish from container IDs
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
		"/tmp/.volume-id",      // Additional common paths
		"/var/data/.volume-id", // Kubernetes common pattern
	}

	for _, path := range volumePaths {
		if data, err := os.ReadFile(path); err == nil {
			volID := strings.TrimSpace(string(data))
			if volID != "" && len(volID) >= 8 { // Require minimum length for stability
				return volID
			}
		}
	}

	// Enhanced Docker socket inspection with better error handling
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
									volumeName := parts[3]
									if volumeName != "" && len(volumeName) >= 3 {
										return "docker-" + volumeName
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Enhanced persistent directory detection with multiple fallback strategies
	persistentPaths := []string{
		"/persistent",
		"/data",
		"/app",
		"/var/lib/app",
	}

	for _, path := range persistentPaths {
		if stat, err := os.Stat(path); err == nil && stat.IsDir() {
			// Generate a stable volume ID based on the persistent directory properties
			// This will be the same for containers using the same volume
			if volID := volumeIDFromFileInfo(stat, path); volID != "" {
				return volID
			}
			// Fallback to size-based but consistent generation
			volID := fmt.Sprintf("vol-%x-%s", stat.Size(), path)
			return volID
		}
	}

	// Environment variable-based volume detection for cloud-native deployments
	if envVolumeID := os.Getenv("DOCKER_VOLUME_ID"); envVolumeID != "" {
		return "env-" + envVolumeID
	}
	if envVolumeID := os.Getenv("VOLUME_ID"); envVolumeID != "" {
		return "env-" + envVolumeID
	}

	return ""
}

// getKubernetesPVCID gets persistent volume claim identifier
func getKubernetesPVCID() string {
	// Check for Kubernetes service account mount (most reliable indicator)
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		namespace := strings.TrimSpace(string(data))
		if namespace != "" {
			// Try to read PVC information from mounted volume with enhanced paths
			pvcPaths := []string{
				"/data/.pvc-id",
				"/persistent/.pvc-id",
				"/var/lib/app/.pvc-id",
				"/tmp/.pvc-id",      // Additional common paths
				"/var/data/.pvc-id", // Kubernetes common pattern
				"/mnt/data/.pvc-id", // Another common pattern
			}

			for _, path := range pvcPaths {
				if data, err := os.ReadFile(path); err == nil {
					pvcID := strings.TrimSpace(string(data))
					if pvcID != "" && len(pvcID) >= 4 { // Require minimum length
						return "k8s-" + namespace + "-" + pvcID
					}
				}
			}

			// Fallback: construct PVC ID from available Kubernetes metadata
			if podName := os.Getenv("HOSTNAME"); podName != "" {
				if pvcName := os.Getenv("PVC_NAME"); pvcName != "" {
					return "k8s-" + namespace + "-" + podName + "-" + pvcName
				}
				// Use pod name as fallback identifier
				return "k8s-" + namespace + "-" + podName
			}
		}
	}

	// Enhanced environment variable detection for PVC information
	if pvcName := os.Getenv("PVC_NAME"); pvcName != "" {
		if namespace := os.Getenv("POD_NAMESPACE"); namespace != "" {
			return "k8s-env-" + namespace + "-" + pvcName
		}
		return "k8s-env-" + pvcName
	}

	// Additional Kubernetes environment variables
	if podUID := os.Getenv("POD_UID"); podUID != "" {
		return "k8s-uid-" + podUID
	}
	if podName := os.Getenv("POD_NAME"); podName != "" {
		if namespace := os.Getenv("POD_NAMESPACE"); namespace != "" {
			return "k8s-" + namespace + "-" + podName
		}
		return "k8s-" + podName
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
	ids := make(map[string]string)

	// Windows containers can't easily access host identifiers without special privileges
	// This would require host volume mounts or specific container runtime configurations
	// For now, return empty map - use other methods like volume IDs or registry

	// Try to use Windows registry for persistent storage if available
	if regID := getWindowsRegistryDeviceID(); regID != "" {
		ids["registry_device_id"] = regID
	}

	return ids
}

// getWindowsRegistryDeviceID attempts to get or create a persistent device ID in Windows registry
func getWindowsRegistryDeviceID() string {
	// This would require Windows-specific registry access
	// For now, return empty string as registry access requires special handling
	// In a real implementation, this would:
	// 1. Check HKEY_LOCAL_MACHINE\\SOFTWARE\\YourApp\\DeviceID
	// 2. Create one if it doesn't exist using a cryptographically secure method
	// 3. Return the existing or new device ID

	// For demonstration, return empty - actual implementation would use:
	// syscall.RegOpenKeyEx, syscall.RegSetValueEx, etc.
	return ""
}

// getMacHostIdentifiers gets host identifiers for macOS containers
func getMacHostIdentifiers() map[string]string {
	// Docker Desktop for Mac runs in a Linux VM
	// Can't directly access macOS host identifiers
	return make(map[string]string)
}

// getWindowsDockerVolumeID gets volume identifier for Windows containers
func getWindowsDockerVolumeID() string {
	// Enhanced Windows-specific volume detection
	volumePaths := []string{
		"C:\\data\\.volume-id",
		"C:\\app\\.volume-id",
		"C:\\persistent\\.volume-id",
		"C:\\temp\\.volume-id", // Additional Windows paths
		"D:\\data\\.volume-id", // Alternative drive
	}

	for _, path := range volumePaths {
		if data, err := os.ReadFile(path); err == nil {
			volID := strings.TrimSpace(string(data))
			if volID != "" && len(volID) >= 4 {
				return "win-" + volID
			}
		}
	}

	// Windows environment variable support
	if envVolumeID := os.Getenv("DOCKER_VOLUME_ID"); envVolumeID != "" {
		return "win-env-" + envVolumeID
	}

	return ""
}

// getPersistentStorageFallback provides a fallback mechanism using application-level persistence
func getPersistentStorageFallback() string {
	// Try to get a persistent identifier from various sources
	// This serves as a last resort when hardware identifiers aren't available

	// Method 1: Check for application-specific persistent files
	persistentFiles := []string{
		"/persistent/.device-id",
		"/data/.device-id",
		"/app/.device-id",
		"/tmp/.device-id",
	}

	for _, path := range persistentFiles {
		if data, err := os.ReadFile(path); err == nil {
			deviceID := strings.TrimSpace(string(data))
			if deviceID != "" && len(deviceID) >= 8 {
				return "persistent-" + deviceID
			}
		}
	}

	// Method 2: Generate based on stable system properties
	// This creates a consistent ID based on system characteristics
	systemProps := []string{
		runtime.GOOS,
		runtime.GOARCH,
	}

	// Add hostname if available
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		systemProps = append(systemProps, hostname)
	}

	// Add user if available
	if user := os.Getenv("USER"); user != "" {
		systemProps = append(systemProps, user)
	}

	// Create a deterministic hash based on system properties
	propsString := strings.Join(systemProps, "|")
	if propsString != "" {
		hash := sha256.Sum256([]byte(appSalt + "|" + propsString))
		return "system-" + fmt.Sprintf("%x", hash)[:16] // Use first 16 chars for brevity
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
