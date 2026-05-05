package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const defaultDotEnvPath = ".env"

func loadDotEnvConfig() error {
	path := strings.TrimSpace(os.Getenv("LICENSE_SERVER_ENV_FILE"))
	if path == "" {
		path = defaultDotEnvPath
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, expected dotenv file", path)
	}

	k := koanf.New(".")
	if err := k.Load(file.Provider(path), dotenv.Parser()); err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}

	for _, key := range k.Keys() {
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, k.String(key)); err != nil {
			return fmt.Errorf("set %s from %s: %w", key, path, err)
		}
	}
	return nil
}
