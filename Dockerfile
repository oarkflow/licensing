# syntax=docker/dockerfile:1.7-labs

########################
# Backend build stage  #
########################
FROM golang:1.25-alpine AS backend-build
WORKDIR /src
ENV CGO_ENABLED=0
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/. .
RUN go build -o /out/crm .

########################
# Backend runtime      #
########################
FROM alpine:latest AS backend
RUN apk add --no-cache ca-certificates wget
WORKDIR /srv
COPY --from=backend-build /out/crm /usr/local/bin/crm
COPY backend/dist ./dist
ENV PORT=5303
EXPOSE 5303
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:5303/api/health || exit 1
CMD ["crm"]
EXPOSE 5303
