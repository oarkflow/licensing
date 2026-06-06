#!/bin/bash

# Quick verification script for security implementation

echo "=========================================="
echo "Security Implementation Verification"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} $1"
        return 0
    else
        echo -e "${RED}✗${NC} $1 (missing)"
        return 1
    fi
}

check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} $1/"
        return 0
    else
        echo -e "${RED}✗${NC} $1/ (missing)"
        return 1
    fi
}

total=0
passed=0

echo "Checking directory structure..."
check_dir "pkg/crypto" && ((passed++))
((total++))
check_dir "pkg/audit" && ((passed++))
((total++))
check_dir "pkg/auth" && ((passed++))
((total++))
check_dir "pkg/integrity" && ((passed++))
((total++))
check_dir "pkg/network" && ((passed++))
((total++))
check_dir "pkg/monitoring" && ((passed++))
((total++))
check_dir "pkg/middleware" && ((passed++))
((total++))
check_dir "pkg/config" && ((passed++))
((total++))
check_dir "pkg/examples" && ((passed++))
((total++))

echo ""
echo "Checking core security files..."
check_file "pkg/crypto/signing.go" && ((passed++))
((total++))
check_file "pkg/crypto/encryption.go" && ((passed++))
((total++))
check_file "pkg/crypto/keyrotation.go" && ((passed++))
((total++))
check_file "pkg/audit/events.go" && ((passed++))
((total++))
check_file "pkg/audit/logger.go" && ((passed++))
((total++))
check_file "pkg/audit/storage.go" && ((passed++))
((total++))
check_file "pkg/auth/rbac.go" && ((passed++))
((total++))
check_file "pkg/integrity/verification.go" && ((passed++))
((total++))
check_file "pkg/integrity/antitamper.go" && ((passed++))
((total++))
check_file "pkg/network/security.go" && ((passed++))
((total++))
check_file "pkg/monitoring/metrics.go" && ((passed++))
((total++))
check_file "pkg/middleware/security.go" && ((passed++))
((total++))
check_file "pkg/config/security.go" && ((passed++))
((total++))
check_file "pkg/examples/secure_server.go" && ((passed++))
((total++))

echo ""
echo "Checking test files..."
check_file "pkg/crypto/signing_test.go" && ((passed++))
((total++))
check_file "pkg/crypto/encryption_test.go" && ((passed++))
((total++))

echo ""
echo "Checking scripts..."
check_file "scripts/setup_secure.sh" && ((passed++))
((total++))

echo ""
echo "Checking documentation..."
check_file "SECURITY_IMPLEMENTATION.md" && ((passed++))
((total++))
check_file "CLIENT_SECURITY.md" && ((passed++))
((total++))
check_file "DEPLOYMENT_SECURITY_CHECKLIST.md" && ((passed++))
((total++))
check_file "SECURITY_SUMMARY.md" && ((passed++))
((total++))
check_file "QUICK_START.md" && ((passed++))
((total++))
check_file "IMPLEMENTATION_COMPLETE.md" && ((passed++))
((total++))

echo ""
echo "=========================================="
echo "Verification Results"
echo "=========================================="
echo -e "Passed: ${GREEN}$passed${NC}/$total"

if [ $passed -eq $total ]; then
    echo -e "${GREEN}✓ All components verified!${NC}"
    echo ""
    echo "Security components are present. Production use still requires the"
    echo "operator controls in docs/PRODUCTION_SQLITE_RUNBOOK.md, including"
    echo "managed secrets, backups, restore drills, monitoring, and access review."
    echo ""
    echo "Next steps:"
    echo "  1. Prepare local profile: make single-node-prepare"
    echo "  2. Validate config: make single-node-check"
    echo "  3. Test: go test ./..."
    echo "  4. Deploy: Follow docs/PRODUCTION_SQLITE_RUNBOOK.md"
    exit 0
else
    echo -e "${RED}✗ Some components missing${NC}"
    exit 1
fi
