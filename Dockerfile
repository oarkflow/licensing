# syntax=docker/dockerfile:1.7-labs

########################
# Backend build stage  #
########################
ARG PLATFORM=linux/amd64
FROM --platform=$PLATFORM golang:1.25-alpine AS backend-build
WORKDIR /src
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/. .
RUN go build -o /out/crm ./cmd

########################
# Backend runtime      #
########################
FROM --platform=$PLATFORM alpine:latest AS backend
RUN apk add --no-cache ca-certificates wget
WORKDIR /srv
COPY --from=backend-build /out/crm /usr/local/bin/crm
COPY backend/templates ./templates
COPY backend/dist ./dist
ENV PORT=6601
EXPOSE 6601
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:6601/api/health || exit 1
CMD ["crm"]
EXPOSE 6601
