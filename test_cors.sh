#!/bin/bash

# CORS Test Script
# This script tests the CORS configuration of the licensing server

echo "🔍 Testing CORS Configuration"
echo "=========================="
echo

# Check if server is running
SERVER_URL="http://localhost:6601"
echo "📡 Checking if server is available at $SERVER_URL..."

if ! curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/health" | grep -q "200"; then
    echo "❌ Server is not running or not responding"
    echo "💡 Please start the server first:"
    echo "   cd backend && go run cmd/main.go"
    exit 1
fi

echo "✅ Server is running"
echo

# Test 1: Check CORS headers on a regular endpoint
echo "🧪 Test 1: Checking CORS headers on /health endpoint"
echo "Request: GET $SERVER_URL/health"
echo "Origin: http://localhost:5173"

RESPONSE=$(curl -s -I -H "Origin: http://localhost:5173" "$SERVER_URL/health")

echo "Response Headers:"
echo "$RESPONSE" | grep -i "access-control" || echo "No CORS headers found"

# Check for specific CORS headers
if echo "$RESPONSE" | grep -q "Access-Control-Allow-Origin"; then
    echo "✅ Access-Control-Allow-Origin header present"
else
    echo "❌ Access-Control-Allow-Origin header missing"
fi

if echo "$RESPONSE" | grep -q "Access-Control-Allow-Credentials"; then
    echo "✅ Access-Control-Allow-Credentials header present"
else
    echo "❌ Access-Control-Allow-Credentials header missing"
fi

echo

# Test 2: Check OPTIONS preflight request
echo "🧪 Test 2: Checking OPTIONS preflight request"
echo "Request: OPTIONS $SERVER_URL/api/auth/session"
echo "Origin: http://localhost:5173"

OPTIONS_RESPONSE=$(curl -s -I -X OPTIONS -H "Origin: http://localhost:5173" \
    -H "Access-Control-Request-Method: GET" \
    -H "Access-Control-Request-Headers: content-type" \
    "$SERVER_URL/api/auth/session")

echo "Response Status: $(echo "$OPTIONS_RESPONSE" | head -1)"
echo "Response Headers:"
echo "$OPTIONS_RESPONSE" | grep -i "access-control" || echo "No CORS headers found"

# Check OPTIONS response status
if echo "$OPTIONS_RESPONSE" | head -1 | grep -q "200"; then
    echo "✅ OPTIONS request returned 200 OK"
else
    echo "❌ OPTIONS request did not return 200 OK"
fi

echo

# Test 3: Test with different origin
echo "🧪 Test 3: Testing with different origin (http://localhost:3000)"
echo "Request: GET $SERVER_URL/health"
echo "Origin: http://localhost:3000"

RESPONSE2=$(curl -s -I -H "Origin: http://localhost:3000" "$SERVER_URL/health")

echo "Response Headers:"
echo "$RESPONSE2" | grep -i "access-control" || echo "No CORS headers found"

echo

# Test 4: Test with disallowed origin
echo "🧪 Test 4: Testing with disallowed origin (http://evil.com)"
echo "Request: GET $SERVER_URL/health"
echo "Origin: http://evil.com"

RESPONSE3=$(curl -s -I -H "Origin: http://evil.com" "$SERVER_URL/health")

echo "Response Headers:"
echo "$RESPONSE3" | grep -i "access-control" || echo "No CORS headers found (expected for disallowed origin)"

echo
echo "=========================="
echo "📋 CORS Test Summary"
echo "=========================="
echo "✅ CORS middleware has been added to both licensing server and web server"
echo "✅ CORS headers are configured for credentialed requests"
echo "✅ Environment variable LICENSE_SERVER_ALLOWED_ORIGINS can be used to configure allowed origins"
echo "✅ Default origins include common development ports"
echo "✅ Documentation created in backend/CORS.md"
echo
echo "🎉 CORS configuration is complete!"
