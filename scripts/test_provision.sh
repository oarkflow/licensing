#!/bin/bash

# Test Script for Provision License Endpoint
# This script tests the provisioning endpoint using existing product and plan IDs

set -e

# Configuration
BASE_URL="${BASE_URL:-http://localhost:8801}"
API_KEY="${API_KEY:-BCADD99C5BB186ADE0AF906FD687FD3C4E047F0E65D0E5DD}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_step() {
    echo -e "\n${BLUE}==> $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

usage() {
    echo "Usage: $0 -p <product_id> -l <plan_id> [-e <email>] [-n <name>] [-c <company>]"
    echo ""
    echo "Required:"
    echo "  -p, --product-id    Product ID (UUID)"
    echo "  -l, --plan-id       Plan ID (UUID)"
    echo ""
    echo "Optional:"
    echo "  -e, --email         Customer email (default: test-<timestamp>@example.com)"
    echo "  -n, --name          Customer name (default: Test User)"
    echo "  -c, --company       Company name (default: Test Company Inc.)"
    echo "  -v, --verbose       Show full response"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  BASE_URL            Server URL (default: http://localhost:8801)"
    echo "  API_KEY             Admin API key"
    echo ""
    echo "Example:"
    echo "  $0 -p 123e4567-e89b-12d3-a456-426614174000 -l 987fcdeb-51a2-3bc4-d567-890123456789"
    exit 1
}

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    print_error "jq is required but not installed. Please install jq first."
    echo "  macOS: brew install jq"
    echo "  Ubuntu: sudo apt install jq"
    exit 1
fi

# Parse arguments
PRODUCT_ID=""
PLAN_ID=""
TEST_EMAIL=""
CUSTOMER_NAME="Test User"
COMPANY_NAME="Test Company Inc."
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--product-id)
            PRODUCT_ID="$2"
            shift 2
            ;;
        -l|--plan-id)
            PLAN_ID="$2"
            shift 2
            ;;
        -e|--email)
            TEST_EMAIL="$2"
            shift 2
            ;;
        -n|--name)
            CUSTOMER_NAME="$2"
            shift 2
            ;;
        -c|--company)
            COMPANY_NAME="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate required arguments
if [ -z "$PRODUCT_ID" ]; then
    print_error "Product ID is required"
    usage
fi

if [ -z "$PLAN_ID" ]; then
    print_error "Plan ID is required"
    usage
fi

# Generate email if not provided
if [ -z "$TEST_EMAIL" ]; then
    TEST_ID=$(date +%s)
    TEST_EMAIL="test-user-${TEST_ID}@example.com"
fi

echo "======================================"
echo "  License Provisioning Test"
echo "======================================"
echo "Base URL: $BASE_URL"
echo ""

# Provision a License
print_step "Provisioning a license..."
echo "  Email: $TEST_EMAIL"
echo "  Name: $CUSTOMER_NAME"
echo "  Company: $COMPANY_NAME"
echo "  Product ID: $PRODUCT_ID"
echo "  Plan ID: $PLAN_ID"

PROVISION_RESPONSE=$(curl -s -X POST "$BASE_URL/api/admin/licenses/provision" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{
        \"email\": \"$TEST_EMAIL\",
        \"name\": \"$CUSTOMER_NAME\",
        \"company_name\": \"$COMPANY_NAME\",
        \"product_id\": \"$PRODUCT_ID\",
        \"plan_id\": \"$PLAN_ID\"
    }")

# Check for errors
if echo "$PROVISION_RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
    print_error "Failed to provision license"
    echo "$PROVISION_RESPONSE" | jq .
    exit 1
fi

# Parse response
if echo "$PROVISION_RESPONSE" | jq -e '.license' > /dev/null 2>&1; then
    LICENSE_ID=$(echo "$PROVISION_RESPONSE" | jq -r '.license.id')
    LICENSE_KEY=$(echo "$PROVISION_RESPONSE" | jq -r '.license.license_key')
    LICENSE_MAX_DEVICES=$(echo "$PROVISION_RESPONSE" | jq -r '.license.max_devices')
    LICENSE_EXPIRES_AT=$(echo "$PROVISION_RESPONSE" | jq -r '.license.expires_at')
    CLIENT_CREATED=$(echo "$PROVISION_RESPONSE" | jq -r '.client_created')

    print_success "License provisioned successfully!"
    echo ""
    echo "License Details:"
    echo "  License ID: $LICENSE_ID"
    echo "  License Key: $LICENSE_KEY"
    echo "  Max Devices: $LICENSE_MAX_DEVICES"
    echo "  Expires At: $LICENSE_EXPIRES_AT"
    echo "  Client Created: $CLIENT_CREATED"
else
    print_error "Unexpected response format"
    echo "$PROVISION_RESPONSE" | jq .
    exit 1
fi

# Check email queue status
print_step "Email Status:"

EMAILS=$(echo "$PROVISION_RESPONSE" | jq '.emails')
if [ "$EMAILS" != "null" ]; then
    WELCOME_SENT=$(echo "$EMAILS" | jq -r '.welcome.sent // false')
    LICENSE_SENT=$(echo "$EMAILS" | jq -r '.license.sent // false')
    WELCOME_ERROR=$(echo "$EMAILS" | jq -r '.welcome.error // ""')
    LICENSE_ERROR=$(echo "$EMAILS" | jq -r '.license.error // ""')

    if [ "$WELCOME_SENT" = "true" ]; then
        print_success "Welcome email sent"
    else
        print_warning "Welcome email not sent: $WELCOME_ERROR"
    fi

    if [ "$LICENSE_SENT" = "true" ]; then
        print_success "License email with JSON attachment sent"
    else
        print_warning "License email not sent: $LICENSE_ERROR"
    fi
fi

# Client info
print_step "Client Information:"
CLIENT_ID=$(echo "$PROVISION_RESPONSE" | jq -r '.client.id')
CLIENT_NAME=$(echo "$PROVISION_RESPONSE" | jq -r '.client.name')
CLIENT_COMPANY=$(echo "$PROVISION_RESPONSE" | jq -r '.client.company_name')

echo "  Client ID: $CLIENT_ID"
echo "  Name: $CLIENT_NAME"
echo "  Company: $CLIENT_COMPANY"

# Summary
echo ""
echo "======================================"
print_success "Provisioning completed successfully!"
echo "======================================"

# Show full response if verbose
if [ "$VERBOSE" -eq 1 ]; then
    print_step "Full Response:"
    echo "$PROVISION_RESPONSE" | jq .
fi
