#!/usr/bin/env bash
set -euo pipefail

SIGNING_KEY="${SIGNING_KEY:-signing-key.pem}"
OUTPUT="${OUTPUT:-device-fingerprint}"
PKG="./cmd/device-fingerprint"

# Step 1: Generate signing key if missing
if [ ! -f "$SIGNING_KEY" ]; then
  echo "=== Generating signing key pair ==="
  go run scripts/sign-fingerprint.go -gen-key -out "$SIGNING_KEY"
fi

# Step 2: Extract public key hex
PUBKEY=$(go run scripts/sign-fingerprint.go -pubkey -key "$SIGNING_KEY")

# Step 3: Build with embedded public key
echo "=== Building device-fingerprint ==="
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}"
go build -ldflags "-s -w -X main.version=$VERSION -X main.embeddedPubKeyHex=$PUBKEY" -o "$OUTPUT" "$PKG"

# Step 4: Sign the binary
echo "=== Signing binary ==="
go run scripts/sign-fingerprint.go -sign "$OUTPUT" -key "$SIGNING_KEY"

# Step 5: Verify the signed binary can validate itself
RUN_OUTPUT="$OUTPUT"
case "$RUN_OUTPUT" in
  */*) ;;
  *) RUN_OUTPUT="./$RUN_OUTPUT" ;;
esac
echo "=== Verifying signed binary ==="
"$RUN_OUTPUT" --version >/dev/null

echo ""
echo "=== Build complete ==="
ls -lh "$OUTPUT"
echo "Public key: $PUBKEY"
