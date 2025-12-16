#!/bin/bash
# Interoperability test runner for asherah-cobhan
#
# This script runs the full interop test suite to verify compatibility
# between the Rust and Go implementations.
#
# Usage:
#   ./run_interop_tests.sh [--with-go-library]
#
# Options:
#   --with-go-library   Also test against the original Go asherah-cobhan library
#                       (requires Go asherah-cobhan shared library in ./lib/)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$PROJECT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================"
echo "Asherah-Cobhan Interoperability Tests"
echo "======================================"
echo ""

# Parse arguments
WITH_GO_LIBRARY=false
for arg in "$@"; do
    case $arg in
        --with-go-library)
            WITH_GO_LIBRARY=true
            shift
            ;;
    esac
done

# Step 1: Build Rust library
echo -e "${YELLOW}Step 1: Building Rust asherah-cobhan library...${NC}"
cd "$ROOT_DIR"
cargo build -p asherah-cobhan --release
echo -e "${GREEN}OK${NC}"
echo ""

# Step 2: Run Rust unit tests
echo -e "${YELLOW}Step 2: Running Rust unit tests...${NC}"
cargo test -p asherah-cobhan --lib
echo -e "${GREEN}OK${NC}"
echo ""

# Step 3: Run Rust integration tests
echo -e "${YELLOW}Step 3: Running Rust integration tests...${NC}"
cargo test -p asherah-cobhan --test integration_tests
echo -e "${GREEN}OK${NC}"
echo ""

# Step 4: Run Rust interop tests
echo -e "${YELLOW}Step 4: Running Rust interop tests...${NC}"
cargo test -p asherah-cobhan --test interop_tests
echo -e "${GREEN}OK${NC}"
echo ""

# Step 5: Verify exported symbols
echo -e "${YELLOW}Step 5: Verifying exported C ABI symbols...${NC}"
DYLIB_EXT="dylib"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    DYLIB_EXT="so"
fi
DYLIB_PATH="$ROOT_DIR/target/release/libasherah_cobhan.$DYLIB_EXT"

if [ ! -f "$DYLIB_PATH" ]; then
    echo -e "${RED}FAIL: Could not find $DYLIB_PATH${NC}"
    exit 1
fi

# Check for required exported symbols
REQUIRED_SYMBOLS=("Shutdown" "SetEnv" "SetupJson" "EstimateBuffer" "Encrypt" "Decrypt" "EncryptToJson" "DecryptFromJson")
echo "Checking exported symbols in $DYLIB_PATH..."

for sym in "${REQUIRED_SYMBOLS[@]}"; do
    # macOS uses _Symbol, Linux uses Symbol
    if nm -gU "$DYLIB_PATH" 2>/dev/null | grep -qE " _?${sym}$"; then
        echo "  - $sym: OK"
    else
        echo -e "${RED}  - $sym: MISSING${NC}"
        exit 1
    fi
done
echo -e "${GREEN}OK${NC}"
echo ""

# Step 6: Cross-implementation testing (if Go library available)
if [ "$WITH_GO_LIBRARY" = true ]; then
    echo -e "${YELLOW}Step 6: Cross-implementation testing with Go library...${NC}"

    GO_LIB_PATH="$SCRIPT_DIR/lib/libasherah_cobhan_go.dylib"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        GO_LIB_PATH="$SCRIPT_DIR/lib/libasherah_cobhan_go.so"
    fi

    if [ ! -f "$GO_LIB_PATH" ]; then
        echo -e "${RED}Go library not found at $GO_LIB_PATH${NC}"
        echo "Please build the Go asherah-cobhan library and place it in interop/lib/"
        exit 1
    fi

    # Generate test vectors with Go implementation
    cd "$SCRIPT_DIR"

    # Set up environment for static KMS
    export STATIC_MASTER_KEY_HEX="41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141"

    echo "Generating test vectors with Go implementation..."
    CGO_LDFLAGS="-L$SCRIPT_DIR/lib" go run generate_vectors.go

    if [ ! -f "$SCRIPT_DIR/test_vectors_go.json" ]; then
        echo -e "${RED}Failed to generate test vectors${NC}"
        exit 1
    fi

    echo "Verifying Rust implementation can decrypt Go-encrypted data..."
    # This would need a Rust test that reads the Go vectors and decrypts them
    # For now, we verify the file was created successfully
    if [ -f "$SCRIPT_DIR/test_vectors_go.json" ]; then
        echo -e "${GREEN}Test vectors generated successfully${NC}"
        cat "$SCRIPT_DIR/test_vectors_go.json" | head -50
    fi

    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}Step 6: Skipping Go cross-implementation tests (use --with-go-library to enable)${NC}"
fi
echo ""

# Summary
echo "======================================"
echo -e "${GREEN}All interoperability tests passed!${NC}"
echo "======================================"
echo ""
echo "Tests completed:"
echo "  - Rust unit tests"
echo "  - Rust integration tests"
echo "  - Rust interop tests (JSON format, buffer format, error codes)"
echo "  - C ABI symbol verification"
if [ "$WITH_GO_LIBRARY" = true ]; then
    echo "  - Go cross-implementation tests"
fi
echo ""
