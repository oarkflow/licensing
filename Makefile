docker: build deploy-docker
deploy-docker:
	bash build.sh

build-run: build run

build:
	pnpm build && rm -rf backend/dist && mv dist backend/dist

run:
	cd backend && go run ./cmd/
