#!/bin/bash
# Build script for Blackworm with OpenSSL integration

set -e  # Exit on error

echo "=== Blackworm OpenSSL Build Script ==="
echo

# Helper function for error handling
cleanup_and_exit() {
    echo "ERROR: $1"
    exit 1
}

# Check required tools
echo "Checking prerequisites..."
for tool in openssl cmake make lake; do
    if ! command -v $tool &>/dev/null; then
        cleanup_and_exit "$tool not found. Please install $tool first."
    fi
done
echo "✓ All tools found"

# Check OpenSSL version
OPENSSL_VERSION=$(openssl version | awk '{print $2}')
OPENSSL_MAJOR=$(echo $OPENSSL_VERSION | cut -d. -f1)

if [ "$OPENSSL_MAJOR" -lt 3 ]; then
    cleanup_and_exit "OpenSSL 3.0 or higher required (found $OPENSSL_VERSION)"
fi
echo "✓ OpenSSL $OPENSSL_VERSION found"

# Detect platform and set OpenSSL path
echo "Detecting platform..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    OPENSSL_PATH=$(brew --prefix openssl@3 2>/dev/null || echo "/usr/local/opt/openssl@3")
    if [ ! -d "$OPENSSL_PATH" ]; then
        OPENSSL_PATH="/usr/local"
    fi
    echo "✓ macOS detected, OpenSSL path: $OPENSSL_PATH"
elif [[ "$OSTYPE" == "linux"* ]]; then
    OPENSSL_PATH="/usr"
    echo "✓ Linux detected"
else
    OPENSSL_PATH="/usr"
    echo "⚠ Unknown platform, using default paths"
fi

# Verify OpenSSL libraries exist
if [ ! -f "$OPENSSL_PATH/lib/libssl.so" ] && [ ! -f "$OPENSSL_PATH/lib/libssl.dylib" ] && \
   [ ! -f "/usr/lib/x86_64-linux-gnu/libssl.so" ] && [ ! -f "/opt/homebrew/opt/openssl/lib/libssl.dylib" ]; then
    echo "⚠ Warning: OpenSSL libraries not found in expected locations"
fi

# Create and clean build directory
if [ -d "build" ]; then
    echo "Cleaning previous build..."
    rm -rf build
fi
mkdir -p build
echo "✓ Created build directory"

# Run CMake
cd build
echo "Running CMake configuration..."
if ! cmake -DOPENSSL_DIR=$OPENSSL_PATH ..; then
    cd ..
    cleanup_and_exit "CMake configuration failed"
fi
echo "✓ CMake configuration complete"

# Build C library
echo "Building OpenSSL FFI library..."
NUM_JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
if ! make -j$NUM_JOBS; then
    cd ..
    cleanup_and_exit "C library build failed"
fi
echo "✓ C library built successfully"

# Return to project root
cd ..

# Build Lean project
echo
echo "Building Lean project with Lake..."
if ! lake build; then
    cleanup_and_exit "Lean build failed"
fi
echo "✓ Lean project built successfully"

echo
echo "=== Build Complete ==="
echo "✓ All components compiled successfully"
echo
echo "You can now use the cryptographic functions in your Lean code."
echo
echo "Example usage:"
echo "  import Blackworm.CryptoInterface"
echo "  open Crypto"
echo "  def main : IO Unit := do"
echo "    let msg := \"Hello\".toUTF8"
echo "    let hash ← hash256 msg"
echo "    IO.println hash.bytes.toHex"
echo
echo "For more information, see:"
echo "  - README_OPENSSL_INTEGRATION.md"
echo "  - INTEGRATION_SUMMARY.md"
echo "  - ALGORITHM_REFERENCE.lean"
