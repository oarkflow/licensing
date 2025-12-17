package commands

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/oarkflow/cli/contracts"
	"github.com/oarkflow/licensing/pkg/config"
	"github.com/oarkflow/migrate"
	"github.com/oarkflow/squealx/drivers/sqlite"
)

func SetupMigration(client contracts.Cli, migrationFS fs.FS, cfg config.LoadOptions) error {
	dir := cfg.MigrationDir
	if dir == "" {
		dir = filepath.Join("static", "migrations")
	}
	seedDir := filepath.Join(dir, "seeds")
	driver := "sqlite"
	migrationTable := cfg.MigrtionTable
	if migrationTable == "" {
		migrationTable = "migrations"
	}
	os.MkdirAll(dir, os.ModePerm)
	files, _ := os.ReadDir(dir)
	if len(files) == 0 {
		os.Create(dir + "/.gitkeep")
	}

	cfg1, err := config.LoadFromEnv(cfg)
	if err != nil {
		return fmt.Errorf("Failed to load configuration: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(cfg1.DatabasePath), 0o755); err != nil {
		return fmt.Errorf("Failed to create database directory: %v", err)
	}

	dbPath := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", cfg1.DatabasePath)

	db, err := sqlite.Open(dbPath, driver)
	if err != nil {
		return fmt.Errorf("Failed to open database: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	migrationDB, err := migrate.NewFromDB(driver, db)
	if err != nil {
		return err
	}
	historyDB, err := migrate.NewDatabaseHistoryDriverFromDB(db, driver, migrationTable)
	if err != nil {
		return err
	}
	manager := migrate.NewManager(
		migrate.WithDriver(migrationDB),
		migrate.WithClient(client),
		migrate.WithMigrationDir(dir),
		migrate.WithHistoryDriver(historyDB),
		migrate.WithSeedDir(seedDir),
		migrate.WithEmbeddedFiles(migrationFS),
	)
	client.Register(migrate.GetCommands(manager))
	return nil
}
