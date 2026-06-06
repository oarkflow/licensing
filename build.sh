#!/bin/bash

# Build and deploy the licensing server image.
# Builds Docker image, exports it, and deploys to server via SSH

set -e

SERVER_USER="${SERVER_USER:?set SERVER_USER}"
SERVER_HOST="${SERVER_HOST:?set SERVER_HOST}"
SERVER_PATH="${SERVER_PATH:?set SERVER_PATH}"
IMAGE_NAME="${IMAGE_NAME:-crm:latest}"
PORT="${SSH_PORT:-22}"
CONTAINER_NAME="${CONTAINER_NAME:-licensing-server}"
TAR_FILE="${TAR_FILE:-licensing-server.tar}"
HTTP_PORT="${LICENSE_SERVER_PORT:-6601}"
SQLITE_PATH="${LICENSE_SERVER_STORAGE_SQLITE_PATH:-/data/licensing.db}"

echo "Building Docker image..."
docker compose build --build-arg PLATFORM=linux/amd64

echo "Saving Docker image to tar file..."
docker save $IMAGE_NAME > $TAR_FILE

echo "Creating directory on server..."
ssh $SERVER_USER@$SERVER_HOST -p $PORT "mkdir -p $SERVER_PATH"

echo "Copying image to server..."
scp -P $PORT $TAR_FILE $SERVER_USER@$SERVER_HOST:$SERVER_PATH/

echo "Deploying on server..."
ssh $SERVER_USER@$SERVER_HOST -p $PORT << EOF
  mkdir -p $SERVER_PATH
  mkdir -p $SERVER_PATH/data
  cd $SERVER_PATH
  echo "Loading Docker image..."
  docker load < $TAR_FILE
  echo "Stopping existing container if running..."
  docker stop $CONTAINER_NAME || true
  docker rm $CONTAINER_NAME || true
  echo "Starting new container..."
  docker run -d \
    --name $CONTAINER_NAME \
    -p $HTTP_PORT:$HTTP_PORT \
    -e LICENSE_SERVER_HTTP_ADDR=":$HTTP_PORT" \
    -e LICENSE_SERVER_STORAGE="sqlite" \
    -e LICENSE_SERVER_STORAGE_SQLITE_PATH="$SQLITE_PATH" \
    -v $SERVER_PATH/data:/data \
    $IMAGE_NAME
  echo "Cleaning up tar file..."
  rm $TAR_FILE
EOF

echo "Cleaning up local tar file..."
rm $TAR_FILE

echo "Deployment complete! Application should be running on $SERVER_HOST:$HTTP_PORT"
