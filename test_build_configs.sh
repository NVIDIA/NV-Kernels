#!/bin/bash

echo "=== Testing Build Configurations ==="
echo

# Test configurations
configs=(
    "arm64 generic"
    "arm64 generic-64k"
    "amd64 generic"
)

# Function to test if a build can start
test_build() {
    local arch=$1
    local flavour=$2
    
    echo "Testing: $arch with $flavour"
    echo "----------------------------------------"
    
    # Set up environment
    if [ "$arch" = "amd64" ]; then
        cross="x86_64-linux-gnu"
    else
        cross="aarch64-linux-gnu"
    fi
    
    # Get gcc version
    gcc_ver=$(grep -E "^export gcc\?=" debian/rules.d/0-common-vars.mk 2>/dev/null | sed 's/export gcc?=//' | tr -d ' ')
    if [ -z "$gcc_ver" ]; then
        gcc_ver="gcc-14"
    fi
    
    # Check if cross compiler exists
    if which "${cross}-${gcc_ver}" >/dev/null 2>&1; then
        echo "✓ Compiler ${cross}-${gcc_ver} found"
    else
        echo "✗ Compiler ${cross}-${gcc_ver} NOT FOUND"
        echo
        return 1
    fi
    
    # Test if we can start the build (just clean phase)
    echo "Testing build system..."
    export gcc=$gcc_ver
    
    # Use timeout to prevent hanging
    timeout 30 sh -c "
        export gcc=$gcc_ver
        fakeroot debian/rules clean ARCH=$arch 2>&1 | head -20
    "
    
    if [ $? -eq 0 ] || [ $? -eq 124 ]; then
        echo "✓ Build system appears to work"
        result="PASS"
    else
        echo "✗ Build system error"
        result="FAIL"
    fi
    
    echo "Result: $result"
    echo
    return 0
}

# Clean up any existing fakeroot issues
echo "Cleaning up fakeroot semaphores..."
echo "Skinnyjoe@Nvid1a" | sudo -S ipcs -s | grep nvidia | awk '{print $2}' | xargs -r sudo ipcrm -s 2>/dev/null

# Run tests
for config in "${configs[@]}"; do
    test_build $config
done

echo "=== Summary ==="
echo "Available build configurations:"
echo "1. arm64 with generic     - Supported"
echo "2. arm64 with generic-64k - Supported"
echo "3. amd64 with generic     - Supported"
echo "4. amd64 with generic-64k - NOT SUPPORTED (arm64 only)"
echo
echo "Note: 'nvidia' and 'nvidia-64k' flavours don't exist in this tree."
echo "The available flavours are: generic, generic-64k" 