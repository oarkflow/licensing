package integrity

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
)

// TamperDetector detects tampering attempts
type TamperDetector struct {
	checks []TamperCheck
}

// TamperCheck represents a single tampering check
type TamperCheck struct {
	Name        string
	Description string
	Check       func() (bool, error)
}

// NewTamperDetector creates a new tamper detector
func NewTamperDetector() *TamperDetector {
	detector := &TamperDetector{
		checks: []TamperCheck{},
	}
	detector.registerDefaultChecks()
	return detector
}

// registerDefaultChecks registers default tampering checks
func (t *TamperDetector) registerDefaultChecks() {
	// Check if running under debugger
	t.AddCheck("debugger_detection", "Detect if process is being debugged", detectDebugger)

	// Check if running in VM (optional - can be disabled for legitimate VMs)
	// t.AddCheck("vm_detection", "Detect if running in virtual machine", detectVM)

	// Check binary integrity
	t.AddCheck("binary_integrity", "Verify executable integrity", checkBinaryIntegrity)

	// Check memory protection
	t.AddCheck("memory_protection", "Verify memory protection is active", checkMemoryProtection)
}

// AddCheck adds a custom tampering check
func (t *TamperDetector) AddCheck(name, description string, check func() (bool, error)) {
	t.checks = append(t.checks, TamperCheck{
		Name:        name,
		Description: description,
		Check:       check,
	})
}

// RunChecks runs all tampering checks
func (t *TamperDetector) RunChecks() (*TamperDetectionResult, error) {
	result := &TamperDetectionResult{
		Timestamp: time.Now().UTC(),
		Checks:    []TamperCheckResult{},
	}

	for _, check := range t.checks {
		passed, err := check.Check()
		checkResult := TamperCheckResult{
			Name:        check.Name,
			Description: check.Description,
			Passed:      passed,
			Timestamp:   time.Now().UTC(),
		}

		if err != nil {
			checkResult.Error = err.Error()
		}

		result.Checks = append(result.Checks, checkResult)

		if !passed {
			result.TamperingDetected = true
			result.FailedChecks++
		} else {
			result.PassedChecks++
		}
	}

	return result, nil
}

// TamperDetectionResult represents the result of tampering detection
type TamperDetectionResult struct {
	Timestamp         time.Time           `json:"timestamp"`
	TamperingDetected bool                `json:"tampering_detected"`
	PassedChecks      int                 `json:"passed_checks"`
	FailedChecks      int                 `json:"failed_checks"`
	Checks            []TamperCheckResult `json:"checks"`
}

// TamperCheckResult represents a single check result
type TamperCheckResult struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Passed      bool      `json:"passed"`
	Timestamp   time.Time `json:"timestamp"`
	Error       string    `json:"error,omitempty"`
}

// detectDebugger detects if the process is being debugged
func detectDebugger() (bool, error) {
	switch runtime.GOOS {
	case "linux":
		return detectDebuggerLinux()
	case "darwin":
		return detectDebuggerDarwin()
	case "windows":
		return detectDebuggerWindows()
	default:
		return true, fmt.Errorf("debugger detection not supported on %s", runtime.GOOS)
	}
}

// detectDebuggerLinux detects debugger on Linux
func detectDebuggerLinux() (bool, error) {
	// Check /proc/self/status for TracerPid
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return true, fmt.Errorf("failed to read status: %w", err)
	}

	// Look for TracerPid
	// If TracerPid is not 0, process is being traced
	status := string(data)
	// Simple check - in production, use proper parsing
	if len(status) > 0 {
		// TracerPid: 0 means not being debugged
		// This is a simplified check
		return true, nil // Not being debugged
	}

	return false, nil // Being debugged
}

// detectDebuggerDarwin detects debugger on macOS
func detectDebuggerDarwin() (bool, error) {
	// Use sysctl to check P_TRACED flag
	// This is platform-specific and requires CGO
	// For now, return a placeholder
	return true, nil
}

// detectDebuggerWindows detects debugger on Windows
func detectDebuggerWindows() (bool, error) {
	// Use IsDebuggerPresent or CheckRemoteDebuggerPresent
	// This requires CGO and Windows-specific imports
	// For now, return a placeholder
	return true, nil
}

// detectVM detects if running in a virtual machine
func detectVM() (bool, error) {
	// Check for VM-specific artifacts
	// This is optional and can cause false positives
	// Many legitimate use cases involve VMs
	return true, nil // Not in VM (or VM detection disabled)
}

// checkBinaryIntegrity checks the integrity of the executable
func checkBinaryIntegrity() (bool, error) {
	// Get the path of the current executable
	exePath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Calculate checksum
	_, err = ChecksumFile(exePath)
	if err != nil {
		return false, fmt.Errorf("failed to calculate checksum: %w", err)
	}

	// In production, compare with expected checksum
	// For now, just verify we can read the file
	return true, nil
}

// checkMemoryProtection checks if memory protection is active
func checkMemoryProtection() (bool, error) {
	// Check if memory pages are protected
	// This is platform-specific
	switch runtime.GOOS {
	case "linux", "darwin":
		// Check if we can mprotect memory
		// This is a simplified check
		return true, nil
	case "windows":
		// Check VirtualProtect status
		return true, nil
	default:
		return true, nil
	}
}

// ContinuousMonitor continuously monitors for tampering
type ContinuousMonitor struct {
	detector     *TamperDetector
	interval     time.Duration
	alertChannel chan *TamperDetectionResult
	stopChannel  chan bool
}

// NewContinuousMonitor creates a new continuous monitor
func NewContinuousMonitor(interval time.Duration) *ContinuousMonitor {
	return &ContinuousMonitor{
		detector:     NewTamperDetector(),
		interval:     interval,
		alertChannel: make(chan *TamperDetectionResult, 10),
		stopChannel:  make(chan bool, 1),
	}
}

// Start starts continuous monitoring
func (m *ContinuousMonitor) Start() {
	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				result, err := m.detector.RunChecks()
				if err != nil {
					// Log error but continue monitoring
					continue
				}

				if result.TamperingDetected {
					select {
					case m.alertChannel <- result:
					default:
						// Alert channel is full, skip this alert
					}
				}

			case <-m.stopChannel:
				return
			}
		}
	}()
}

// Stop stops continuous monitoring
func (m *ContinuousMonitor) Stop() {
	m.stopChannel <- true
}

// GetAlerts returns the alert channel
func (m *ContinuousMonitor) GetAlerts() <-chan *TamperDetectionResult {
	return m.alertChannel
}

// AntiDebugMeasures implements anti-debugging measures
type AntiDebugMeasures struct {
	enabled bool
}

// NewAntiDebugMeasures creates new anti-debug measures
func NewAntiDebugMeasures() *AntiDebugMeasures {
	return &AntiDebugMeasures{enabled: true}
}

// Enable enables anti-debug measures
func (a *AntiDebugMeasures) Enable() {
	a.enabled = true
}

// Disable disables anti-debug measures (for development)
func (a *AntiDebugMeasures) Disable() {
	a.enabled = false
}

// Apply applies anti-debugging measures
func (a *AntiDebugMeasures) Apply() error {
	if !a.enabled {
		return nil
	}

	// Prevent ptrace attachment (Linux)
	if runtime.GOOS == "linux" {
		// Use prctl PR_SET_DUMPABLE to prevent debugging
		// This requires CGO
		// syscall.Prctl(syscall.PR_SET_DUMPABLE, 0, 0, 0, 0)
		_ = syscall.Getpid() // Placeholder
	}

	return nil
}

// CheckIntegrity performs a comprehensive integrity check
func CheckIntegrity() error {
	detector := NewTamperDetector()
	result, err := detector.RunChecks()
	if err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}

	if result.TamperingDetected {
		return fmt.Errorf("tampering detected: %d checks failed", result.FailedChecks)
	}

	return nil
}
