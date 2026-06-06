docker: build deploy-docker
deploy-docker:
	bash build.sh

build-run: build run

build:
	cd web && pnpm install && pnpm build && rm -rf ../dist && mv dist ../dist

run:
	go run ./cmd/

run-distribution:
	go run -tags distribution ./cmd/

build-distribution:
	go build -tags distribution -o licensing-server ./cmd/

docker-distribution:
	docker compose build --build-arg PLATFORM=linux/amd64 --build-arg GO_BUILD_TAGS=distribution
