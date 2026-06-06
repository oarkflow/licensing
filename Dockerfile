# syntax=docker/dockerfile:1.7-labs

########################
# Backend build stage  #
########################
ARG PLATFORM=linux/amd64
ARG GO_BUILD_TAGS=""
FROM --platform=$PLATFORM golang:1.25-alpine AS backend-build
ARG GO_BUILD_TAGS
WORKDIR /src
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN if [ -n "$GO_BUILD_TAGS" ]; then \
      go build -tags "$GO_BUILD_TAGS" -o /out/crm ./cmd; \
    else \
      go build -o /out/crm ./cmd; \
    fi

########################
# Backend runtime      #
########################
FROM --platform=$PLATFORM alpine:latest AS backend
RUN apk add --no-cache ca-certificates wget
RUN addgroup -S licensing && adduser -S -D -h /home/licensing -s /sbin/nologin -G licensing licensing
WORKDIR /srv
COPY --from=backend-build /out/crm /usr/local/bin/crm
COPY templates ./templates
COPY dist ./dist
RUN mkdir -p /data /home/licensing/.licensing && chown -R licensing:licensing /srv /data /home/licensing
USER licensing
ENV PORT=6601
EXPOSE 6601
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:6601/health || exit 1
CMD ["crm"]
EXPOSE 6601
