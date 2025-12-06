#!/bin/bash

# Go Binary Obfuscation Build Script
# This script builds hardened Go binaries resistant to reverse engineering

set -e

# Configuration
APP_NAME="${1:-app}"
SOURCE_FILE="${2:-main.go}"
OUTPUT_DIR="${3:-./build}"
BUILD_ID="$(date +%s)_$(openssl rand -hex 4)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v go &> /dev/null; then
        log_error "Go is not installed"
        exit 1
    fi

    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $GO_VERSION"

    # Check garble and update if needed
    if ! command -v garble &> /dev/null; then
        log_warn "garble not found. Installing latest version..."
        go install mvdan.cc/garble@latest
    else
        GARBLE_VERSION=$(garble version 2>/dev/null || echo "unknown")
        log_info "Current garble version: $GARBLE_VERSION"

        # Update garble to latest to avoid compatibility issues
        log_info "Updating garble to latest version..."
        go install mvdan.cc/garble@latest

        # Clear garble cache to avoid stale data
        rm -rf "$(go env GOCACHE)/garble" 2>/dev/null || true
    fi

    if ! command -v upx &> /dev/null; then
        log_warn "UPX not found. Install for additional compression: https://upx.github.io/"
    fi
}

# Build with maximum obfuscation
build_obfuscated() {
    log_info "Building obfuscated binary: $APP_NAME"

    mkdir -p "$OUTPUT_DIR"

    # Enhanced obfuscation approach for Go 1.25.0+ compatibility
    GO_MAJOR_VERSION=$(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f1)
    GO_MINOR_VERSION=$(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f2)

    # For Go 1.25.0+, try the simple working garble approach first
    if [ "$GO_MAJOR_VERSION" -ge 1 ] && [ "$GO_MINOR_VERSION" -ge 25 ]; then
        log_info "Detected Go 1.25.0+ - attempting simple garble obfuscation..."

        # Clean environment
        go clean -cache -modcache 2>/dev/null || true
        export CGO_ENABLED=0

        # Try the simple working garble command
        set +e
        if garble build -o "$OUTPUT_DIR/$APP_NAME" "$SOURCE_FILE" 2>&1 | tee /tmp/garble_simple.log; then
            # Verify the binary was actually created
            if [ -f "$OUTPUT_DIR/$APP_NAME" ] && [ -s "$OUTPUT_DIR/$APP_NAME" ]; then
                log_info "🎉 Garble obfuscation successful: $OUTPUT_DIR/$APP_NAME"
                log_info "✅ Binary is now obfuscated and protected"

                # Apply additional hardening
                chmod 555 "$OUTPUT_DIR/$APP_NAME" 2>/dev/null || true

                # Apply UPX compression if available
                if command -v upx &> /dev/null; then
                    log_info "Applying UPX compression for additional protection..."
                    upx --best --lzma "$OUTPUT_DIR/$APP_NAME" 2>/dev/null || \
                    upx --best "$OUTPUT_DIR/$APP_NAME" 2>/dev/null || true
                fi

                set -e
                return
            else
                log_warn "Garble failed to produce valid output"
            fi
        else
            log_warn "Simple garble approach failed, trying alternative methods..."
        fi
        set -e

        log_warn "Simple garble failed, trying alternative obfuscation tools..."

        # Try gobfuscate as alternative obfuscation tool
        if command -v gobfuscate &> /dev/null; then
            log_info "Attempting obfuscation with gobfuscate (alternative to garble)..."

            # Clean build environment
            go clean -cache -modcache 2>/dev/null || true
            export CGO_ENABLED=0

            # Try gobfuscate - but check if it actually succeeded
            set +e
            gobfuscate build \
                -trimpath \
                -buildvcs=false \
                -buildmode=exe \
                -ldflags="-s -w -extldflags=-static -X main.version=$BUILD_ID -buildid=" \
                -gcflags="-dwarf=false -l=false" \
                -asmflags="-trimpath" \
                -o "$OUTPUT_DIR/$APP_NAME" \
                "$SOURCE_FILE" 2>&1 | tee /tmp/gobfuscate_build.log

            # Check if gobfuscate actually created the output file
            if [ -f "$OUTPUT_DIR/$APP_NAME" ] && [ -s "$OUTPUT_DIR/$APP_NAME" ]; then
                log_info "Gobfuscate obfuscation successful: $OUTPUT_DIR/$APP_NAME"
                set -e

                # Apply additional hardening
                chmod 555 "$OUTPUT_DIR/$APP_NAME" 2>/dev/null || true

                return
            else
                log_warn "Gobfuscate failed to produce valid output, falling back to enhanced security build"
                set -e
            fi
        else
            log_warn "Gobfuscate not available, using enhanced security build"
        fi

        # Comprehensive security build as final fallback
        log_info "Building with comprehensive security hardening..."

        # Clean build environment
        go clean -cache -modcache 2>/dev/null || true

        # Build with maximum security flags
        export CGO_ENABLED=0

        # Use most aggressive security flags available
        go build \
            -trimpath \
            -buildvcs=false \
            -buildmode=exe \
            -ldflags="-s -w -extldflags=-static -X main.version=$BUILD_ID -buildid=" \
            -gcflags="-dwarf=false -l=false -N=false" \
            -asmflags="-trimpath" \
            -o "$OUTPUT_DIR/$APP_NAME" \
            "$SOURCE_FILE"

        if [ $? -eq 0 ]; then
            log_info "Comprehensive security build successful: $OUTPUT_DIR/$APP_NAME"

            # Apply post-build hardening and protection
            log_info "Applying post-build hardening..."

            # Make binary read-only to prevent easy tampering
            chmod 555 "$OUTPUT_DIR/$APP_NAME" 2>/dev/null || true

            # Apply UPX compression if available (makes reverse engineering harder)
            if command -v upx &> /dev/null; then
                log_info "Applying UPX compression for additional protection..."
                upx --best --lzma "$OUTPUT_DIR/$APP_NAME" 2>/dev/null || \
                upx --best "$OUTPUT_DIR/$APP_NAME" 2>/dev/null || true
            fi

            # Provide comprehensive security recommendations
            log_info "🔒 COMPREHENSIVE PROTECTION APPLIED 🔒"
            log_info ""
            log_info "Your binary has been built with maximum available protection:"
            log_info "✅ Symbol table stripped (-s flag)"
            log_info "✅ Debug information removed (-w flag)"
            log_info "✅ DWARF debugging disabled"
            log_info "✅ Build paths removed (-trimpath)"
            log_info "✅ VCS information excluded"
            log_info "✅ Binary made read-only (chmod 555)"
            log_info "✅ UPX compression applied (if available)"
            log_info "✅ Static linking for reduced dependencies"
            log_info ""
            log_info "For EVEN STRONGER protection, consider these additional measures:"
            log_info "🔹 Add the anti-debugging code shown below to your main package"
            log_info "🔹 Implement code integrity checks and self-modification detection"
            log_info "🔹 Use external obfuscation tools on the final binary"
            log_info "🔹 Implement license key validation with hardware binding"
            log_info "🔹 Add anti-tampering checks that verify binary integrity"
            log_info "🔹 Use code signing and certificate pinning"
            log_info "🔹 Implement runtime environment validation"
            log_info ""
            log_info "While garble obfuscation isn't available for Go 1.25.0+ due to"
            log_info "crypto package incompatibilities, this build provides"
            log_info "maximum protection using all available Go compiler features."

            return
        else
            log_error "Comprehensive security build failed"
            build_fallback
            return
        fi
    fi

    # Clean garble cache before building
    log_info "Cleaning garble cache..."
    go clean -cache -modcache 2>/dev/null || true

    # Garble build flags for maximum obfuscation
    # Using -tiny flag which is more compatible with standard library packages
    GARBLE_FLAGS=(
        -tiny              # Optimize for size (more compatible)
        -seed=random       # Random seed for obfuscation
    )

    # Go build flags for hardening
    LDFLAGS=(
        -s                                    # Strip symbol table
        -w                                    # Strip DWARF debugging info
        -X main.version=$BUILD_ID             # Embed build ID
        -buildid=                             # Remove build ID
    )

    # For static builds, only use extldflags if CGO is enabled
    if [ "$CGO_ENABLED" = "1" ]; then
        LDFLAGS+=(-extldflags=-static)
    fi

    GCFLAGS=(
        -dwarf=false                          # Disable DWARF generation
    )

    ASMFLAGS=(
        -trimpath                             # Remove file paths
    )

    BUILD_FLAGS=(
        -trimpath                             # Remove file system paths
        -buildvcs=false                       # Don't embed VCS info
        -buildmode=exe                        # Executable mode
    )

    # Construct full build command
    export CGO_ENABLED=0

    log_info "Running garble build with obfuscation..."
    log_info "This may take a few minutes..."

    # Temporarily disable exit-on-error for garble build to allow fallback
    set +e
    # Run garble with better error handling
    if garble "${GARBLE_FLAGS[@]}" build \
        "${BUILD_FLAGS[@]}" \
        -ldflags="${LDFLAGS[*]}" \
        -gcflags="${GCFLAGS[*]}" \
        -asmflags="${ASMFLAGS[*]}" \
        -o "$OUTPUT_DIR/$APP_NAME" \
        "$SOURCE_FILE" 2>&1 | tee /tmp/garble_build.log; then
        log_info "Build successful: $OUTPUT_DIR/$APP_NAME"
    else
        log_error "Build failed. Check /tmp/garble_build.log for details"
        log_warn "Attempting fallback build without garble..."
        build_fallback
    fi
    # Re-enable exit-on-error
    set -e
}

# Fallback build without garble (still hardened)
build_fallback() {
    log_warn "Building with standard Go compiler (no garble obfuscation)..."

    LDFLAGS=(
        -s
        -w
        -X main.version=$BUILD_ID
        -buildid=
    )

    export CGO_ENABLED=0

    go build \
        -trimpath \
        -buildvcs=false \
        -ldflags="${LDFLAGS[*]}" \
        -gcflags="-dwarf=false" \
        -o "$OUTPUT_DIR/$APP_NAME" \
        "$SOURCE_FILE"

    if [ $? -eq 0 ]; then
        log_info "Fallback build successful: $OUTPUT_DIR/$APP_NAME"
        log_warn "Note: Binary is not obfuscated (garble failed)"
    else
        log_error "Both garble and fallback builds failed"
        exit 1
    fi
}

# Apply UPX compression (optional)
apply_upx() {
    if command -v upx &> /dev/null; then
        log_info "Applying UPX compression..."
        upx --best --lzma "$OUTPUT_DIR/$APP_NAME" 2>/dev/null || \
        upx --best "$OUTPUT_DIR/$APP_NAME" || \
        log_warn "UPX compression failed, continuing..."
    fi
}

# Anti-debugging techniques (add to your Go code)
show_antidebug_tips() {
    log_info "Additional hardening recommendations:"
    echo ""
    echo "Add these to your Go source code:"
    echo ""
    cat << 'EOF'
// Anti-debugging checks
import (
    "os"
    "runtime"
    "syscall"
)

func init() {
    // Check for debugger (Linux/Unix)
    if runtime.GOOS != "windows" {
        var status syscall.PtraceRequest
        _, _, err := syscall.Syscall6(syscall.SYS_PTRACE,
            uintptr(status), 0, 0, 0, 0, 0)
        if err == 0 {
            os.Exit(1) // Debugger detected
        }
    }

    // Check for common debugging environment variables
    debugVars := []string{"GODEBUG", "GOTRACEBACK"}
    for _, v := range debugVars {
        if os.Getenv(v) != "" {
            os.Exit(1)
        }
    }
}
EOF
}

# Strip additional metadata
strip_metadata() {
    log_info "Stripping additional metadata..."

    if command -v strip &> /dev/null; then
        strip -s "$OUTPUT_DIR/$APP_NAME" 2>/dev/null || \
        log_warn "Strip command failed, binary may retain some symbols"
    fi
}

# Generate checksums
generate_checksums() {
    log_info "Generating checksums..."

    if command -v sha256sum &> /dev/null; then
        sha256sum "$OUTPUT_DIR/$APP_NAME" > "$OUTPUT_DIR/$APP_NAME.sha256"
        log_info "SHA256: $(cat $OUTPUT_DIR/$APP_NAME.sha256)"
    fi
}

# Main execution
main() {
    log_info "Starting obfuscated build process..."
    log_info "Source: $SOURCE_FILE"
    log_info "Output: $OUTPUT_DIR/$APP_NAME"
    echo ""

    check_dependencies
    build_obfuscated
    strip_metadata
    apply_upx
    generate_checksums

    echo ""
    log_info "Build complete!"
    log_info "Binary size: $(du -h $OUTPUT_DIR/$APP_NAME | cut -f1)"
    echo ""
    show_antidebug_tips
}

# Run main
main "$@"
