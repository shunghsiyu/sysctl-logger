#!/bin/bash
# Auto-format all C source files using clang-format

set -e

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Check if running from project root
if [ ! -f "sysctl-logger.c" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

# Check if clang-format is available
if ! command -v clang-format &> /dev/null; then
    echo "Error: clang-format is not installed"
    echo "Install it with:"
    echo "  Ubuntu/Debian: sudo apt-get install clang-format"
    echo "  SUSE/openSUSE: sudo zypper install clang"
    exit 1
fi

echo_info "Formatting C source files..."

# Format all .c and .h files (excluding output directory and generated files)
FORMATTED=0
while IFS= read -r file; do
    echo "  Formatting: $file"
    clang-format -i "$file"
    FORMATTED=$((FORMATTED + 1))
done < <(find . -name "*.c" -o -name "*.h" | grep -v "output/" | grep -v "vmlinux.h")

echo_info "Formatted $FORMATTED file(s)"
echo_info "Done!"
