package main

import (
	"embed"
	"io/fs"
	"log"
	"os"

	"github.com/oarkflow/cli"
	"github.com/oarkflow/cli/console"
	"github.com/oarkflow/cli/contracts"
	"github.com/oarkflow/licensing/pkg/commands"
	"github.com/oarkflow/licensing/pkg/config"
	"github.com/oarkflow/licensing/pkg/utils"
)

//go:embed dist/**
var embeddedFiles embed.FS

//go:embed static/migrations/**
var migrationFiles embed.FS

func getFileSystem() fs.FS {
	// Get the subtree of the embedded files with `dist` directory as the root
	public, err := fs.Sub(embeddedFiles, "dist")
	if err != nil {
		log.Fatal(err)
	}
	return public
}

func main() {
	os.Setenv("LICENSE_SERVER_ALLOW_INSECURE_HTTP", "true")
	cli.Run("Licensing Server", "1.0.0", RegisterCommands)
}

func RegisterCommands(client contracts.Cli) []contracts.Command {
	publicFs := getFileSystem()
	path, err := utils.GetDBPath("LICENSE_SERVER_STORAGE_SQLITE_PATH", ".licensing", "data", "licensing.db")
	if err != nil {
		path = "licensing.db"
	}
	commands.SetupMigration(client, migrationFiles, config.LoadOptions{FilePath: path})
	return []contracts.Command{
		commands.NewServer(client, publicFs),
		console.NewListCommand(client),
	}
}
