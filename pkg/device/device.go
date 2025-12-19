package device

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

// NIST SP 800-57: Device fingerprint is not a cryptographic key, but is used to bind
// secrets to a specific device as an additional security control. It is not used for
// encryption or key derivation.

type DeviceInfo struct {
	Name        string              `json:"name"`
	Fingerprint string              `json:"fingerprint"`
	Platform    string              `json:"platform"`
	Label       string              `json:"label"`
	Identifiers map[string]string   `json:"identifiers"`
	Hardware    map[string]string   `json:"hardware"`
	Signals     map[string][]string `json:"signals,omitempty"`
}

func GetInfo() (*DeviceInfo, error) {
	info := &DeviceInfo{
		Platform:    runtime.GOOS,
		Identifiers: make(map[string]string),
		Hardware:    make(map[string]string),
		Signals:     make(map[string][]string),
	}
	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		info.Name = host
	}
	var idErr error
	switch runtime.GOOS {
	case "windows":
		info.Identifiers, idErr = getWindowsIdentifiers()
		info.Hardware = getWindowsHardwareInfo()
	case "darwin":
		info.Identifiers, idErr = getMacIdentifiers()
		info.Hardware = getMacHardwareInfo()
	case "linux":
		info.Identifiers, idErr = getLinuxIdentifiers()
		info.Hardware = getLinuxHardwareInfo()
	default:
		return nil, fmt.Errorf("unsupported platform")
	}
	if idErr != nil {
		return nil, fmt.Errorf("identifier error: %v", idErr)
	}
	enrichDeviceSignals(info)
	extraParts := append(mapValues(info.Hardware), flattenSignalValues(info.Signals)...)
	fingerprint, err := generateFingerprint(info.Identifiers, extraParts...)
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

func generateFingerprint(ids map[string]string, extra ...string) (string, error) {
	keys := make([]string, 0, len(ids))
	for k := range ids {
		if v := strings.TrimSpace(ids[k]); v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, strings.TrimSpace(ids[k]))
	}
	for _, v := range extra {
		if val := strings.TrimSpace(v); val != "" {
			parts = append(parts, val)
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no identifiers available")
	}
	hash := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return fmt.Sprintf("%x", hash), nil
}

func mapValues(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var values []string
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			values = append(values, v)
		}
	}
	return values
}

func flattenSignalValues(signals map[string][]string) []string {
	if len(signals) == 0 {
		return nil
	}
	keys := make([]string, 0, len(signals))
	for k := range signals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var values []string
	for _, k := range keys {
		items := append([]string(nil), signals[k]...)
		sort.Strings(items)
		for _, v := range items {
			if val := strings.TrimSpace(v); val != "" {
				values = append(values, val)
			}
		}
	}
	return values
}

func enrichDeviceSignals(info *DeviceInfo) {
	if macs := getMACAddresses(); len(macs) > 0 {
		info.Signals["mac_addresses"] = macs
		if info.Hardware["primary_mac"] == "" {
			info.Hardware["primary_mac"] = macs[0]
		}
	}
	if disks := getDiskSerials(); len(disks) > 0 {
		info.Signals["disk_serials"] = disks
	}
	switch runtime.GOOS {
	case "linux":
		if boot := getLinuxBootID(); boot != "" {
			info.Identifiers["boot_id"] = boot
		}
	case "darwin":
		if serial := getMacSerialNumber(); serial != "" {
			info.Identifiers["system_serial"] = serial
		}
	case "windows":
		if serial := getWindowsSystemSerial(); serial != "" {
			info.Identifiers["system_serial"] = serial
		}
		if board := getWindowsBoardSerial(); board != "" {
			info.Identifiers["baseboard_serial"] = board
		}
	}
}

func getWindowsIdentifiers() (map[string]string, error) {
	ids := make(map[string]string)
	cmd := exec.Command("wmic", "csproduct", "get", "UUID")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			ids["bios_uuid"] = strings.TrimSpace(lines[1])
		}
	}
	cmd = exec.Command("reg", "query",
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
		"/v", "MachineGuid")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\r\n")
		for _, line := range lines {
			if strings.Contains(line, "MachineGuid") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					ids["machine_guid"] = parts[len(parts)-1]
				}
			}
		}
	}
	if serial := getWindowsSystemSerial(); serial != "" {
		ids["system_serial"] = serial
	}
	if board := getWindowsBoardSerial(); board != "" {
		ids["baseboard_serial"] = board
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("failed to get Windows identifiers")
	}
	return ids, nil
}

func getWindowsHardwareInfo() map[string]string {
	info := make(map[string]string)
	if output, err := exec.Command("wmic", "computersystem", "get", "manufacturer,model").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			parts := strings.Fields(lines[1])
			if len(parts) >= 2 {
				info["manufacturer"] = parts[0]
				info["model"] = strings.Join(parts[1:], " ")
			}
		}
	}
	if output, err := exec.Command("wmic", "cpu", "get", "name").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			info["cpu"] = strings.TrimSpace(lines[1])
		}
	}
	if output, err := exec.Command("wmic", "memorychip", "get", "capacity").Output(); err == nil {
		var total uint64
		lines := strings.Split(string(output), "\n")
		for _, line := range lines[1:] {
			if cp := strings.TrimSpace(line); cp != "" {
				var bytes uint64
				_, _ = fmt.Sscanf(cp, "%d", &bytes)
				total += bytes
			}
		}
		if total > 0 {
			info["memory"] = fmt.Sprintf("%d GB", total/1024/1024/1024)
		}
	}
	return info
}

func getMacIdentifiers() (map[string]string, error) {
	ids := make(map[string]string)
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.Split(line, " = ")
				if len(parts) == 2 {
					ids["platform_uuid"] = strings.Trim(parts[1], "\"")
				}
			}
			if strings.Contains(line, "IOPlatformSerialNumber") {
				parts := strings.Split(line, " = ")
				if len(parts) == 2 {
					ids["system_serial"] = strings.Trim(parts[1], "\"")
				}
			}
		}
	}
	if _, exists := ids["platform_uuid"]; !exists {
		cmd = exec.Command("system_profiler", "SPHardwareDataType")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "Hardware UUID") {
					parts := strings.Split(line, ": ")
					if len(parts) == 2 {
						ids["hardware_uuid"] = strings.TrimSpace(parts[1])
					}
				}
				if strings.Contains(line, "Serial Number") {
					parts := strings.Split(line, ": ")
					if len(parts) == 2 {
						ids["system_serial"] = strings.TrimSpace(parts[1])
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

func getMacHardwareInfo() map[string]string {
	info := make(map[string]string)
	cmd := exec.Command("sysctl", "-n", "hw.model")
	if output, err := cmd.Output(); err == nil {
		info["model"] = strings.TrimSpace(string(output))
	}
	cmd = exec.Command("system_profiler", "SPHardwareDataType")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Chip") {
				parts := strings.Split(line, ": ")
				if len(parts) == 2 {
					info["cpu"] = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "Memory") {
				parts := strings.Split(line, ": ")
				if len(parts) == 2 {
					info["memory"] = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return info
}

func getLinuxIdentifiers() (map[string]string, error) {
	ids := make(map[string]string)
	if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		ids["dmi_uuid"] = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		ids["machine_id"] = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/sys/class/dmi/id/board_serial"); err == nil {
		ids["board_serial"] = strings.TrimSpace(string(data))
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("failed to get Linux identifiers")
	}
	return ids, nil
}

func getLinuxHardwareInfo() map[string]string {
	info := make(map[string]string)
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		info["manufacturer"] = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		info["model"] = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/sys/class/dmi/id/bios_version"); err == nil {
		info["bios_version"] = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "model name") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					info["cpu"] = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal") {
				parts := strings.Fields(line)
				if len(parts) == 3 {
					info["memory"] = fmt.Sprintf("%s %s", parts[1], parts[2])
				}
			}
		}
	}
	return info
}

func GetDeviceFingerPrint() (string, error) {
	deviceInfo, err := GetInfo()
	if err != nil {
		return "", fmt.Errorf("error getting device info: %v", err)
	}
	return deviceInfo.Fingerprint, nil
}

func getMACAddresses() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var macs []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if hw := iface.HardwareAddr; len(hw) >= 6 && isGloballyAdministeredMAC(hw) {
			macs = append(macs, hw.String())
		}
	}
	sort.Strings(macs)
	return macs
}

func isGloballyAdministeredMAC(hw net.HardwareAddr) bool {
	// IEEE: locally administered addresses have bit 1 of first octet set
	if len(hw) < 6 {
		return false
	}
	return hw[0]&0x02 == 0
}

func getDiskSerials() []string {
	switch runtime.GOOS {
	case "linux":
		return getLinuxDiskSerials()
	case "windows":
		return getWindowsDiskSerials()
	case "darwin":
		return getDarwinDiskSerials()
	}
	return nil
}

func getLinuxDiskSerials() []string {
	entries, err := os.ReadDir("/dev/disk/by-id/")
	if err != nil {
		return nil
	}
	var serials []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "ata-") || strings.HasPrefix(name, "nvme-") {
			if !strings.Contains(name, "-part") {
				serials = append(serials, name)
			}
		}
	}
	sort.Strings(serials)
	return serials
}

func getWindowsDiskSerials() []string {
	output, err := exec.Command("wmic", "diskdrive", "get", "SerialNumber").Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(output), "\n")
	var serials []string
	for _, line := range lines[1:] {
		if serial := strings.TrimSpace(line); serial != "" {
			serials = append(serials, serial)
		}
	}
	sort.Strings(serials)
	return serials
}

func getDarwinDiskSerials() []string {
	output, err := exec.Command("system_profiler", "SPSerialATADataType").Output()
	if err != nil {
		return nil
	}
	var serials []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "Serial Number") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				serials = append(serials, strings.TrimSpace(parts[1]))
			}
		}
	}
	sort.Strings(serials)
	return serials
}

func getLinuxBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
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

func getMacSerialNumber() string {
	output, err := exec.Command("system_profiler", "SPHardwareDataType").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "Serial Number") {
			parts := strings.Split(line, ": ")
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
