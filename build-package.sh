#!/bin/bash

# Script to build Debian package for libpkce
set -e

echo "Building libpkce Debian package..."

# Clean any previous builds
echo "Cleaning previous builds..."
make distclean || true
rm -rf debian/tmp debian/.debhelper debian/files
rm -rf debian/libpkce0* debian/libpkce-dev* debian/pkce-tools*

# Regenerate build system
echo "Regenerating build system..."
./autogen.sh

# Build the package
echo "Building Debian package..."
dpkg-buildpackage -us -uc -b

echo "Build complete!"
echo "Generated packages:"
ls -la ../*.deb

echo ""
echo "To install the packages:"
echo "sudo dpkg -i ../libpkce0_*.deb ../libpkce-dev_*.deb ../pkce-tools_*.deb"
echo "sudo apt-get install -f  # Fix any dependency issues"
