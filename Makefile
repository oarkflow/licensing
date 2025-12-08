docker: build deploy-docker
deploy-docker:
	bash build.sh

build-run: build run

build:
	cd web && pnpm install && pnpm build && rm -rf ../dist && mv dist ../dist

run:
	go run ./cmd/
