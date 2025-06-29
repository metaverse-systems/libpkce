# Debian Packaging for libpkce

This directory contains the Debian packaging files for libpkce.

## Building the Package

### Prerequisites

Install the required build dependencies:

```bash
sudo apt-get install build-essential debhelper-compat autotools-dev autoconf automake libtool pkg-config libssl-dev
```

### Building

1. **Automatic build** (recommended):
   ```bash
   ./build-package.sh
   ```

2. **Manual build**:
   ```bash
   # Clean and regenerate build system
   make distclean || true
   ./autogen.sh
   
   # Build the package
   dpkg-buildpackage -us -uc -b
   ```

### Generated Packages

The build process creates three packages:

- **libpkce0**: Shared library runtime package
- **libpkce-dev**: Development headers and static library
- **pkce-tools**: Command-line tools

### Installation

```bash
sudo dpkg -i ../libpkce0_*.deb ../libpkce-dev_*.deb ../pkce-tools_*.deb
sudo apt-get install -f  # Fix any dependency issues
```

## Package Contents

### libpkce0
- `/usr/lib/*/libpkce.so.*` - Shared library

### libpkce-dev  
- `/usr/include/libpkce/` - Header files in subdirectory
- `/usr/lib/*/libpkce.so` - Development symlink
- `/usr/lib/*/libpkce.a` - Static library  
- `/usr/lib/*/pkgconfig/libpkce.pc` - pkg-config file

### pkce-tools
- `/usr/bin/pkce` - Command-line utility

## Lintian Checks

After building, you can check the packages for common issues:

```bash
lintian ../*.deb
```
