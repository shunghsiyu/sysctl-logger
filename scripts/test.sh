#!/bin/bash
# Local test script that mirrors CI checks
# Run this before committing to ensure CI will pass

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running from project root
if [ ! -f "sysctl-logger.c" ]; then
    echo_error "Please run this script from the project root directory"
    exit 1
fi

# Check dependencies
echo_info "Checking dependencies..."
MISSING_DEPS=()
MISSING_OPTIONAL=()

for cmd in clang gcc make; do
    if ! command -v "$cmd" &> /dev/null; then
        MISSING_DEPS+=("$cmd")
    fi
done

# Check optional dependencies
for cmd in bpftool clang-format; do
    if ! command -v "$cmd" &> /dev/null; then
        MISSING_OPTIONAL+=("$cmd")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo_error "Missing required dependencies: ${MISSING_DEPS[*]}"
    echo_info "Install them with:"
    echo "  Ubuntu/Debian: sudo apt-get install clang gcc make libbpf-dev libelf-dev zlib1g-dev"
    echo "  SUSE/openSUSE: sudo zypper install clang gcc make libbpf-devel libelf-devel zlib-devel"
    exit 1
fi

if [ ${#MISSING_OPTIONAL[@]} -gt 0 ]; then
    echo_warn "Missing optional dependencies: ${MISSING_OPTIONAL[*]}"
    echo_info "Some checks may be skipped. To install:"
    echo "  Ubuntu/Debian: sudo apt-get install linux-tools-generic clang-format"
    echo "  SUSE/openSUSE: sudo zypper install bpftool clang"
fi

# Check code formatting
if command -v clang-format &> /dev/null; then
    echo_info "Checking code formatting..."
    FORMATTING_ISSUES=0
    while IFS= read -r file; do
        if ! clang-format --dry-run --Werror "$file" 2>/dev/null; then
            echo_warn "Formatting issues in: $file"
            echo "  Fix with: clang-format -i $file"
            FORMATTING_ISSUES=$((FORMATTING_ISSUES + 1))
        fi
    done < <(find . -name "*.c" -o -name "*.h" | grep -v "output/" | grep -v "vmlinux.h")

    if [ $FORMATTING_ISSUES -gt 0 ]; then
        echo_warn "Found formatting issues in $FORMATTING_ISSUES file(s)"
        echo_info "You can auto-fix all files by running: ./scripts/format.sh"
    else
        echo_info "Code formatting: PASSED"
    fi
else
    echo_warn "Skipping code formatting check (clang-format not available)"
    FORMATTING_ISSUES=0
fi

# Clean build
echo_info "Running clean build..."
make clean > /dev/null 2>&1
if ! make V=1; then
    echo_error "Build failed"
    exit 1
fi
echo_info "Build: PASSED"

# Build with strict warnings
echo_info "Building with strict warnings (-Werror)..."
make clean > /dev/null 2>&1
if ! CFLAGS="-g -Wall -Wextra -Werror" make V=1 2>&1 | tee /tmp/build.log; then
    echo_error "Build failed with strict warnings"
    echo_error "See build output above for details"
    exit 1
fi
echo_info "Strict build: PASSED"

# Verify binary
if [ ! -f sysctl-logger ]; then
    echo_error "Binary 'sysctl-logger' was not created"
    exit 1
fi
echo_info "Binary verification: PASSED"

# Summary
echo ""
echo_info "========================================="
echo_info "All checks passed!"
echo_info "========================================="
if [ $FORMATTING_ISSUES -gt 0 ]; then
    echo_warn "Note: There are formatting issues, but build succeeded"
    echo_warn "Consider running: ./scripts/format.sh"
fi

exit 0
