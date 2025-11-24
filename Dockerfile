# syntax=docker/dockerfile:1.6

##############################
# Builder image
##############################
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Install build dependencies for CGO/SQLite driver
RUN apk add --no-cache build-base pkgconf

# Cache go modules first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build the server binary (CGO required for modern SQLite driver)
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -o /out/licensing-server ./cmd/server

##############################
# Runtime image
##############################
FROM alpine:3.20 AS runtime

ENV LICENSING_HOME=/app \
    LICENSE_SERVER_HTTP_ADDR=:8801 \
    LICENSE_SERVER_STORAGE=sqlite \
    LICENSE_SERVER_STORAGE_SQLITE_PATH=/data/licensing.db

# Install certs + sqlite runtime deps, create user
RUN apk add --no-cache ca-certificates tzdata sqlite-libs curl \
    && adduser -D -u 10001 licensing

WORKDIR ${LICENSING_HOME}

# Copy compiled binary
COPY --from=builder /out/licensing-server ${LICENSING_HOME}/licensing-server

# Create data directory for sqlite and cert material
RUN mkdir -p /data /certs \
    && chown -R licensing:licensing /data /certs ${LICENSING_HOME}

EXPOSE 8801
VOLUME ["/data", "/certs"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8801/health || exit 1

USER licensing

ENTRYPOINT ["/app/licensing-server"]
