package main

import (
	"encoding/json"
	"examples/http-server/device"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type DeviceResponse struct {
	DeviceInfo *device.DeviceInfo `json:"device_info"`
	Timestamp  time.Time          `json:"timestamp"`
}

type FingerprintResponse struct {
	Fingerprint string    `json:"fingerprint"`
	Timestamp   time.Time `json:"timestamp"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create persistent volume directory if it doesn't exist
	persistentDir := "/persistent"
	if err := os.MkdirAll(persistentDir, 0755); err != nil {
		log.Printf("Warning: Could not create persistent directory: %v", err)
	}

	// Create volume ID file if it doesn't exist
	volumeIDFile := persistentDir + "/.volume-id"
	if _, err := os.Stat(volumeIDFile); os.IsNotExist(err) {
		volumeID := generateVolumeID()
		if err := os.WriteFile(volumeIDFile, []byte(volumeID), 0644); err != nil {
			log.Printf("Warning: Could not write volume ID file: %v", err)
		} else {
			log.Printf("Created new volume ID: %s", volumeID)
		}
	}

	// Create PVC ID file for Kubernetes
	pvcIDFile := persistentDir + "/.pvc-id"
	if _, err := os.Stat(pvcIDFile); os.IsNotExist(err) {
		pvcID := generatePVCID()
		if err := os.WriteFile(pvcIDFile, []byte(pvcID), 0644); err != nil {
			log.Printf("Warning: Could not write PVC ID file: %v", err)
		} else {
			log.Printf("Created new PVC ID: %s", pvcID)
		}
	}

	// HTTP handlers
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status": "healthy", "timestamp": "%s"}`, time.Now().Format(time.RFC3339))
	})

	http.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		deviceInfo, err := device.GetInfo()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error getting device info: %v", err), http.StatusInternalServerError)
			return
		}

		response := DeviceResponse{
			DeviceInfo: deviceInfo,
			Timestamp:  time.Now(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/fingerprint", func(w http.ResponseWriter, r *http.Request) {
		fingerprint, err := device.GetDeviceFingerPrint()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error getting fingerprint: %v", err), http.StatusInternalServerError)
			return
		}

		response := FingerprintResponse{
			Fingerprint: fingerprint,
			Timestamp:   time.Now(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/volume-id", func(w http.ResponseWriter, r *http.Request) {
		volumeIDFile := "/persistent/.volume-id"
		if data, err := os.ReadFile(volumeIDFile); err == nil {
			w.Header().Set("Content-Type", "text/plain")
			w.Write(data)
		} else {
			http.Error(w, "Volume ID not found", http.StatusNotFound)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Device Fingerprint Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .card { background: #f5f5f5; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .endpoint { background: #e3f2fd; padding: 15px; border-radius: 4px; margin: 10px 0; }
        .fingerprint { font-family: monospace; background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; margin: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Device Fingerprint Server</h1>
        <p>This server demonstrates device fingerprinting in Docker containers with persistence.</p>

        <div class="card">
            <h3>API Endpoints</h3>
            <div class="endpoint">
                <strong>GET /health</strong> - Health check
            </div>
            <div class="endpoint">
                <strong>GET /device</strong> - Full device information
            </div>
            <div class="endpoint">
                <strong>GET /fingerprint</strong> - Device fingerprint only
            </div>
            <div class="endpoint">
                <strong>GET /volume-id</strong> - Persistent volume identifier
            </div>
        </div>

        <div class="card">
            <h3>Current Device Information</h3>
            <div id="device-info" class="fingerprint">Loading...</div>
            <button onclick="refreshDeviceInfo()">Refresh</button>
        </div>

        <div class="card">
            <h3>Current Fingerprint</h3>
            <div id="fingerprint" class="fingerprint">Loading...</div>
            <button onclick="refreshFingerprint()">Refresh</button>
        </div>

        <div class="card">
            <h3>Volume ID</h3>
            <div id="volume-id" class="fingerprint">Loading...</div>
            <button onclick="refreshVolumeID()">Refresh</button>
        </div>
    </div>

    <script>
        async function fetchData(url, elementId) {
            try {
                const response = await fetch(url);
                const data = await response.text();
                document.getElementById(elementId).textContent = data;
            } catch (error) {
                document.getElementById(elementId).textContent = 'Error: ' + error.message;
            }
        }

        async function fetchJSON(url, elementId) {
            try {
                const response = await fetch(url);
                const data = await response.json();
                document.getElementById(elementId).textContent = JSON.stringify(data, null, 2);
            } catch (error) {
                document.getElementById(elementId).textContent = 'Error: ' + error.message;
            }
        }

        function refreshDeviceInfo() {
            fetchJSON('/device', 'device-info');
        }

        function refreshFingerprint() {
            fetchJSON('/fingerprint', 'fingerprint');
        }

        function refreshVolumeID() {
            fetchData('/volume-id', 'volume-id');
        }

        // Initial load
        refreshDeviceInfo();
        refreshFingerprint();
        refreshVolumeID();
    </script>
</body>
</html>
`)
	})

	log.Printf("Starting server on port %s", port)
	log.Printf("Server is running in container: %t", device.IsRunningInContainer())
	log.Printf("Persistent volume path: %s", persistentDir)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// generateVolumeID creates a simple volume identifier
func generateVolumeID() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("vol-%s-%d", hostname, time.Now().Unix())
}

// generatePVCID creates a simple PVC identifier
func generatePVCID() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("pvc-%s-%d", hostname, time.Now().Unix())
}
