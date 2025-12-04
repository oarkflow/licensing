#!/bin/bash

# Build script for Secretr Landing Page
# Builds Docker image, exports it, and deploys to server via SSH

set -e

# Configuration - Update these variables
SERVER_USER="spbaniya"
SERVER_HOST="144.126.143.123"
SERVER_PATH="/home/spbaniya/Sites/secretr/crm"
IMAGE_NAME="crm:latest"
PORT=32689
CONTAINER_NAME="crm"
TAR_FILE="crm.tar"

echo "Building Docker image..."
docker compose build

echo "Saving Docker image to tar file..."
docker save $IMAGE_NAME > $TAR_FILE

echo "Copying image to server..."
scp -P $PORT $TAR_FILE $SERVER_USER@$SERVER_HOST:$SERVER_PATH/
scp -P $PORT backend/.env.prod $SERVER_USER@$SERVER_HOST:$SERVER_PATH/

echo "Deploying on server..."
ssh $SERVER_USER@$SERVER_HOST -p $PORT << EOF
  cd $SERVER_PATH
  echo "Loading Docker image..."
  docker load < $TAR_FILE
  echo "Stopping existing container if running..."
  docker stop $CONTAINER_NAME || true
  docker rm $CONTAINER_NAME || true
  echo "Starting new container..."
  docker run -d \
    --name $CONTAINER_NAME \
    -p 6601:6601 \
    --env-file .env.prod \
    $IMAGE_NAME
  echo "Cleaning up tar file..."
  rm $TAR_FILE
EOF

echo "Cleaning up local tar file..."
rm $TAR_FILE

echo "Deployment complete! Application should be running on $SERVER_HOST:6601"
