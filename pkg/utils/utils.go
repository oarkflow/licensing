package utils

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func HashAPIKeys(keys []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		hash := sha256.Sum256([]byte(trimmed))
		copyHash := make([]byte, len(hash))
		copy(copyHash, hash[:])
		hashes = append(hashes, copyHash)
	}
	if len(hashes) == 0 {
		return nil, fmt.Errorf("no valid API keys provided")
	}
	return hashes, nil
}

func ParseAPIKeys(raw string) []string {
	parts := strings.Split(raw, ",")
	keys := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		keys = append(keys, trimmed)
	}
	return keys
}

func GetDBPath(envKey string, defaultPath ...string) (string, error) {
	path := strings.TrimSpace(os.Getenv(envKey))
	if path == "" {
		// Default to ~/.licensing/data/licensing.db
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(append([]string{homeDir}, defaultPath...)...)
	} else {
		path = filepath.Clean(path)
	}
	return path, nil
}
