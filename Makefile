docker: build deploy-docker
deploy-docker:
	bash build.sh

SQLITE_DB ?= $(CURDIR)/data/licensing.db
BACKUP_DIR ?= $(CURDIR)/backups
RESTORE_HEALTH_URL ?=
LOCAL_SINGLE_NODE_ENV ?= $(CURDIR)/.env.single-node
LOCAL_SINGLE_NODE_DIR ?= $(CURDIR)/runtime/single-node

build-run: build run

build:
	cd web && pnpm install && pnpm build && rm -rf ../dist && mv dist ../dist

run:
	go run ./cmd/

check-config:
	go run ./cmd/ check-config

run-distribution:
	go run -tags distribution ./cmd/

build-distribution:
	go build -tags distribution -o licensing-server ./cmd/

docker-distribution:
	docker compose build --build-arg PLATFORM=linux/amd64 --build-arg GO_BUILD_TAGS=distribution

migrate:
	migrator cli migrate --verbose=true

migrate-status:
	migrator cli status

seed-catalog:
	migrator cli seed --include-raw=true --verbose=true

backup-sqlite:
	scripts/backup_sqlite.sh "$(SQLITE_DB)" "$(BACKUP_DIR)"

restore-sqlite-verify:
	scripts/restore_sqlite_verify.sh "$(BACKUP_FILE)" "$(SQLITE_DB)" "$(RESTORE_HEALTH_URL)"

single-node-prepare:
	LOCAL_SINGLE_NODE_ENV="$(LOCAL_SINGLE_NODE_ENV)" LOCAL_SINGLE_NODE_DIR="$(LOCAL_SINGLE_NODE_DIR)" scripts/local_single_node_setup.sh

single-node-check:
	GOCACHE="$(LOCAL_SINGLE_NODE_DIR)/go-build-cache" LICENSE_SERVER_ENV_FILE="$(LOCAL_SINGLE_NODE_ENV)" go run ./cmd/ check-config

single-node-run:
	GOCACHE="$(LOCAL_SINGLE_NODE_DIR)/go-build-cache" LICENSE_SERVER_ENV_FILE="$(LOCAL_SINGLE_NODE_ENV)" go run ./cmd/

single-node-backup:
	LICENSE_SERVER_ENV_FILE="$(LOCAL_SINGLE_NODE_ENV)" LICENSE_SERVER_BACKUP_MARKER_FILE="$(LOCAL_SINGLE_NODE_DIR)/backups/latest.json" scripts/backup_sqlite.sh "$(LOCAL_SINGLE_NODE_DIR)/data/licensing.db" "$(LOCAL_SINGLE_NODE_DIR)/backups"

# Device fingerprinting tool
fingerprint-keygen:
	go build -ldflags "-s -w" -o device-keygen ./cmd/device-keygen

fingerprint-build:
	bash scripts/build-fingerprint.sh

fingerprint: fingerprint-build

fingerprint-all: fingerprint-keygen fingerprint-build

single-node-rehearse:
	APP_ENV=production LICENSE_SERVER_ENV_FILE="$(LOCAL_SINGLE_NODE_ENV)" SQLITE_DB="$(LOCAL_SINGLE_NODE_DIR)/data/licensing.db" BACKUP_DIR="$(LOCAL_SINGLE_NODE_DIR)/backups" AUDIT_DB="$(LOCAL_SINGLE_NODE_DIR)/data/audit.db" MIGRATOR_DIR="$(LOCAL_SINGLE_NODE_DIR)" LICENSING_SERVER_BIN="$(LOCAL_SINGLE_NODE_DIR)/licensing-server" scripts/production_rehearsal.sh
