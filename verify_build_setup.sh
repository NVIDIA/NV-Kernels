#!/bin/bash

echo "=== Build Setup Verification ==="
echo

# Function to get gcc version from debian rules
get_debian_gcc_version() {
    local gcc_version=""
    
    # Check debian/rules.d/0-common-vars.mk first
    if [ -f "debian/rules.d/0-common-vars.mk" ]; then
        gcc_version=$(grep -E "^export gcc\?=" debian/rules.d/0-common-vars.mk | sed 's/export gcc?=//' | tr -d ' ')
    fi
    
    # If not found, check debian.master/rules.d/0-common-vars.mk
    if [ -z "$gcc_version" ] && [ -f "debian.master/rules.d/0-common-vars.mk" ]; then
        gcc_version=$(grep -E "^export gcc\?=" debian.master/rules.d/0-common-vars.mk | sed 's/export gcc?=//' | tr -d ' ')
    fi
    
    echo "$gcc_version"
}

# Get default gcc version
DEFAULT_GCC_VER=$(get_debian_gcc_version)
echo "1. Detected default GCC version: $DEFAULT_GCC_VER"
echo

# Check available flavours
echo "2. Available flavours from debian.master/control.d/:"
ls -1 debian.master/control.d/vars.* 2>/dev/null | sed 's/.*vars\./  - /' || echo "  - No flavour files found"
echo

# Check if required compilers are installed
echo "3. Checking compiler availability:"
for arch in amd64 arm64; do
    if [ "$arch" = "amd64" ]; then
        cross="x86_64-linux-gnu"
    else
        cross="aarch64-linux-gnu"
    fi
    
    compiler="${cross}-${DEFAULT_GCC_VER}"
    if which $compiler >/dev/null 2>&1; then
        echo "  ✓ $compiler found"
    else
        echo "  ✗ $compiler NOT FOUND"
    fi
done
echo

# Check debian packaging structure
echo "4. Checking debian packaging structure:"
for file in debian/rules debian.master/changelog debian.master/control.stub.in; do
    if [ -f "$file" ]; then
        echo "  ✓ $file exists"
    else
        echo "  ✗ $file NOT FOUND"
    fi
done
echo

# Check build dependencies
echo "5. Checking some key build dependencies:"
for tool in fakeroot make dpkg-architecture; do
    if which $tool >/dev/null 2>&1; then
        echo "  ✓ $tool found"
    else
        echo "  ✗ $tool NOT FOUND"
    fi
done
echo

# Show what builds would be attempted
echo "6. Build configurations to test:"
echo "  a) arm64 with nvidia"
echo "  b) arm64 with nvidia-64k" 
echo "  c) amd64 with nvidia"
echo "  d) amd64 with nvidia-64k"
echo

# Check if flavours exist
echo "7. Checking if requested flavours are valid:"
for flavour in nvidia nvidia-64k; do
    if [ -f "debian.master/control.d/vars.$flavour" ]; then
        echo "  ✓ $flavour is a valid flavour"
        # Show which architectures this flavour supports
        arch_line=$(grep "^arch=" "debian.master/control.d/vars.$flavour" 2>/dev/null)
        if [ -n "$arch_line" ]; then
            echo "    Supported architectures: $arch_line"
        fi
    else
        echo "  ✗ $flavour flavour NOT FOUND"
    fi
done 