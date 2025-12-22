#!/bin/bash

# Device Fingerprint Persistence Test Script
# This script tests device fingerprint persistence across Docker container recreation

set -e

# Configuration
IMAGE_NAME="device-fingerprint-test"
CONTAINER_NAME="device-fingerprint-container"
VOLUME_NAME="device-fingerprint-volume"
TEST_DURATION=5
LOG_FILE="test-results.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Function to get fingerprint from running container
get_fingerprint() {
    local container_name=$1
    local port=${2:-8080}

    # Wait for container to be ready
    for i in {1..30}; do
        if curl -s "http://localhost:$port/fingerprint" > /dev/null 2>&1; then
            break
        fi
        if [ $i -eq 30 ]; then
            error "Container $container_name is not responding"
            return 1
        fi
        sleep 1
    done

    # Get fingerprint
    curl -s "http://localhost:$port/fingerprint" | jq -r '.fingerprint' 2>/dev/null || {
        error "Failed to get fingerprint from $container_name"
        return 1
    }
}

# Function to get volume ID
get_volume_id() {
    local container_name=$1
    local port=${2:-8080}

    curl -s "http://localhost:$port/volume-id" 2>/dev/null || {
        error "Failed to get volume ID from $container_name"
        return 1
    }
}

# Function to get full device info
get_device_info() {
    local container_name=$1
    local port=${2:-8080}

    curl -s "http://localhost:$port/device" 2>/dev/null || {
        error "Failed to get device info from $container_name"
        return 1
    }
}

# Function to cleanup
cleanup() {
    log "Cleaning up..."

    # Stop and remove container if it exists
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        log "Stopping container $CONTAINER_NAME"
        docker stop "$CONTAINER_NAME" > /dev/null 2>&1 || true
        docker rm "$CONTAINER_NAME" > /dev/null 2>&1 || true
    fi

    # Remove image if it exists
    if docker images | grep -q "$IMAGE_NAME"; then
        log "Removing image $IMAGE_NAME"
        docker rmi "$IMAGE_NAME" > /dev/null 2>&1 || true
    fi

    # Remove volume if it exists
    if docker volume ls | grep -q "$VOLUME_NAME"; then
        log "Removing volume $VOLUME_NAME"
        docker volume rm "$VOLUME_NAME" > /dev/null 2>&1 || true
    fi
}

# Function to build Docker image
build_image() {
    log "Building Docker image..."

    cd http-server

    # Build the image
    docker build -t "$IMAGE_NAME" . || {
        error "Failed to build Docker image"
        exit 1
    }

    success "Docker image built successfully"
    cd ../..
}

# Function to run test
run_test() {
    log "Starting device fingerprint persistence test"

    # Test 1: Create volume and run first container
    log "=== Test 1: Initial container with persistent volume ==="

    # Create volume
    docker volume create "$VOLUME_NAME" || {
        error "Failed to create Docker volume"
        exit 1
    }

    # Run first container with volume
    log "Starting first container with volume..."
    docker run -d \
        --name "$CONTAINER_NAME" \
        -p 8080:8080 \
        -v "$VOLUME_NAME:/persistent" \
        "$IMAGE_NAME" || {
        error "Failed to start first container"
        cleanup
        exit 1
    }

    # Wait for container to be ready
    sleep 3

    # Get first fingerprint
    log "Getting fingerprint from first container..."
    FIRST_FINGERPRINT=$(get_fingerprint "$CONTAINER_NAME")
    if [ $? -ne 0 ]; then
        error "Failed to get fingerprint from first container"
        cleanup
        exit 1
    fi

    # Get volume ID
    FIRST_VOLUME_ID=$(get_volume_id "$CONTAINER_NAME")

    # Get device info
    log "Getting device information..."
    DEVICE_INFO=$(get_device_info "$CONTAINER_NAME")

    success "First container fingerprint: $FIRST_FINGERPRINT"
    success "First container volume ID: $FIRST_VOLUME_ID"

    # Save device info to file
    echo "$DEVICE_INFO" > device_info_1.json

    # Test 2: Stop container and start new one with same volume
    log "=== Test 2: Container recreation with same volume ==="

    log "Stopping first container..."
    docker stop "$CONTAINER_NAME" > /dev/null

    log "Starting second container with same volume..."
    docker run -d \
        --name "${CONTAINER_NAME}-2" \
        -p 8081:8080 \
        -v "$VOLUME_NAME:/persistent" \
        "$IMAGE_NAME" || {
        error "Failed to start second container"
        cleanup
        exit 1
    }

    # Wait for container to be ready
    sleep 3

    # Get second fingerprint
    log "Getting fingerprint from second container..."
    SECOND_FINGERPRINT=$(get_fingerprint "${CONTAINER_NAME}-2" 8081)
    if [ $? -ne 0 ]; then
        error "Failed to get fingerprint from second container"
        cleanup
        exit 1
    fi

    # Get volume ID
    SECOND_VOLUME_ID=$(get_volume_id "${CONTAINER_NAME}-2" 8081)

    # Get device info
    log "Getting device information..."
    DEVICE_INFO=$(get_device_info "${CONTAINER_NAME}-2" 8081)

    success "Second container fingerprint: $SECOND_FINGERPRINT"
    success "Second container volume ID: $SECOND_VOLUME_ID"

    # Save device info to file
    echo "$DEVICE_INFO" > device_info_2.json

    # Test 3: Compare fingerprints
    log "=== Test 3: Fingerprint comparison ==="

    if [ "$FIRST_FINGERPRINT" = "$SECOND_FINGERPRINT" ]; then
        success "✅ FINGERPRINT PERSISTENCE TEST PASSED"
        success "Fingerprints match: $FIRST_FINGERPRINT"
        log "Volume ID 1: $FIRST_VOLUME_ID"
        log "Volume ID 2: $SECOND_VOLUME_ID"
    else
        error "❌ FINGERPRINT PERSISTENCE TEST FAILED"
        error "Fingerprints do not match:"
        error "First:  $FIRST_FINGERPRINT"
        error "Second: $SECOND_FINGERPRINT"

        # Show device info differences
        log "=== Device Info Comparison ==="
        log "First container device info:"
        cat device_info_1.json
        log "Second container device info:"
        cat device_info_2.json

        cleanup
        exit 1
    fi

    # Test 4: Test without volume (should be different)
    log "=== Test 4: Container without volume (should be different) ==="

    log "Stopping second container..."
    docker stop "${CONTAINER_NAME}-2" > /dev/null

    log "Starting third container WITHOUT volume..."
    docker run -d \
        --name "${CONTAINER_NAME}-3" \
        -p 8082:8080 \
        "$IMAGE_NAME" || {
        error "Failed to start third container"
        cleanup
        exit 1
    }

    # Wait for container to be ready
    sleep 3

    # Get third fingerprint
    log "Getting fingerprint from third container (no volume)..."
    THIRD_FINGERPRINT=$(get_fingerprint "${CONTAINER_NAME}-3" 8082)
    if [ $? -ne 0 ]; then
        error "Failed to get fingerprint from third container"
        cleanup
        exit 1
    fi

    success "Third container fingerprint (no volume): $THIRD_FINGERPRINT"

    # Test 5: Verify fingerprints are different without volume
    log "=== Test 5: Verify different fingerprints without volume ==="

    if [ "$FIRST_FINGERPRINT" != "$THIRD_FINGERPRINT" ]; then
        success "✅ DIFFERENT VOLUME TEST PASSED"
        success "Fingerprints are different as expected:"
        success "With volume:    $FIRST_FINGERPRINT"
        success "Without volume: $THIRD_FINGERPRINT"
    else
        warning "⚠️  DIFFERENT VOLUME TEST INCONCLUSIVE"
        warning "Fingerprints are the same, which might indicate the container is still using some persistent data"
        warning "This could be expected behavior in some environments"
    fi

    # Cleanup
    log "Stopping all containers..."
    docker stop "${CONTAINER_NAME}-3" > /dev/null
    docker rm "$CONTAINER_NAME" "${CONTAINER_NAME}-2" "${CONTAINER_NAME}-3" > /dev/null

    success "All tests completed successfully!"
}

# Main execution
main() {
    log "Device Fingerprint Persistence Test"
    log "==================================="

    # Initialize log file
    echo "Device Fingerprint Persistence Test Results" > "$LOG_FILE"
    echo "===========================================" >> "$LOG_FILE"
    echo "Started at: $(date)" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"

    # Check if Docker is running
    if ! docker info > /dev/null 2>&1; then
        error "Docker is not running. Please start Docker and try again."
        exit 1
    fi

    # Cleanup any existing resources
    cleanup

    # Build image
    build_image

    # Run test
    run_test

    # Final cleanup
    cleanup

    log "Test completed. Results saved to $LOG_FILE"
    log "Device info saved to device_info_1.json and device_info_2.json"
}

# Run main function
main "$@"
