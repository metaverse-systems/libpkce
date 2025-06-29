#!/bin/bash

# Script to validate Debian packaging setup
set -e

echo "Validating libpkce Debian package setup..."

# Check required build tools
echo "Checking build dependencies..."
required_tools=("dpkg-buildpackage" "dh" "autoconf" "automake" "libtool" "pkg-config")
missing_tools=()

for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "Missing required tools: ${missing_tools[*]}"
    echo "Install with: sudo apt-get install build-essential debhelper autotools-dev autoconf automake libtool pkg-config libssl-dev"
    exit 1
fi

# Check if libssl-dev is installed
if ! pkg-config --exists openssl; then
    echo "Missing libssl-dev package"
    echo "Install with: sudo apt-get install libssl-dev"
    exit 1
fi

echo "All build dependencies are satisfied!"

# Validate debian/control syntax
echo "Validating debian/control..."
if ! grep -q "^Source: libpkce" debian/control; then
    echo "ERROR: debian/control seems malformed"
    exit 1
fi

# Check if all required files exist
echo "Checking required Debian files..."
required_files=(
    "debian/control"
    "debian/changelog" 
    "debian/rules"
    "debian/copyright"
    "debian/source/format"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Missing required file: $file"
        exit 1
    fi
done

echo "All required Debian files are present!"

# Check if autogen.sh exists and is executable
if [ ! -x "./autogen.sh" ]; then
    echo "ERROR: autogen.sh is missing or not executable"
    exit 1
fi

echo "✓ Debian packaging setup is valid!"
echo ""
echo "To build the package, run:"
echo "  ./build-package.sh"
echo ""
echo "Or manually:"
echo "  ./autogen.sh"
echo "  dpkg-buildpackage -us -uc -b"
