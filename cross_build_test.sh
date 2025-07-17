#!/bin/bash

ARCH=$1
FLAVOUR=$2
IS_BUILD_TOOL="true"

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

# Get default gcc version from debian files
DEFAULT_GCC_VER=$(get_debian_gcc_version)

# If user didn't specify gcc versions, use the debian default or fallback values
if [ -z "$AMD64_GCC_VER" ]; then
    if [ -n "$DEFAULT_GCC_VER" ]; then
        AMD64_GCC_VER="$DEFAULT_GCC_VER"
    else
        AMD64_GCC_VER="gcc-11"  # Fallback if no debian default found
    fi
fi

if [ -z "$ARM64_GCC_VER" ]; then
    if [ -n "$DEFAULT_GCC_VER" ]; then
        ARM64_GCC_VER="$DEFAULT_GCC_VER"
    else
        ARM64_GCC_VER="gcc-12"  # Fallback if no debian default found
    fi
fi

echo "Using AMD64_GCC_VER: $AMD64_GCC_VER"
echo "Using ARM64_GCC_VER: $ARM64_GCC_VER"

if [ "${IS_BUILD_TOOL}" == "true" ]; then
        BUILD_TOOL_STR="binary-perarch do_linux_tools=true"
else
        BUILD_TOOL_STR="binary-perarch do_linux_tools=false"
fi

if [ "${ARCH}" == "amd64" ]; then
        echo "Debug: AMD64_GCC_VER=${AMD64_GCC_VER}"
        export gcc=${AMD64_GCC_VER}
        echo "Debug: gcc=${gcc}"
        echo "Skinnyjoe@Nvid1a" | sudo -S dpkg-architecture -aamd64 > /tmp/dpkg_arch_amd64.tmp
        export $(cat /tmp/dpkg_arch_amd64.tmp); export CROSS_COMPILE=x86_64-linux-gnu-;
        rm -f /tmp/dpkg_arch_amd64.tmp
        time env CONCURRENCY_LEVEL=$(nproc) \
		sh -c "export gcc=${AMD64_GCC_VER}; rm -f ../*.deb; fakeroot debian/rules clean && debian/rules build do_zfs=false do_mstflint_access=false do_nvidia-fs=false do_skip_checks=true && ./scripts/config --file ./debian/build/build-nvidia/.config --set-val CONFIG_CC_VERSION_TEXT x86_64-linux-gnu-${AMD64_GCC_VER}; \
		fakeroot debian/rules binary-headers binary-${FLAVOUR} \
		${BUILD_TOOL_STR} do_zfs=false do_mstflint_access=false do_nvidia-fs=false do_skip_checks=true; echo \$? > build_lock" 2>&1 | tee build.log
elif [ "${ARCH}" == "arm64" ]; then
        echo "Debug: ARM64_GCC_VER=${ARM64_GCC_VER}"
        export gcc=${ARM64_GCC_VER}
        echo "Debug: gcc=${gcc}"
        echo "Skinnyjoe@Nvid1a" | sudo -S dpkg-architecture -aarm64 > /tmp/dpkg_arch_arm64.tmp
        export $(cat /tmp/dpkg_arch_arm64.tmp); export CROSS_COMPILE=aarch64-linux-gnu-;
        rm -f /tmp/dpkg_arch_arm64.tmp
        time env CONCURRENCY_LEVEL=$(nproc) \
		sh -c "export gcc=${ARM64_GCC_VER}; rm -f ../*.deb; fakeroot debian/rules clean && debian/rules build do_zfs=false do_mstflint_access=false do_nvidia-fs=false do_skip_checks=true && fakeroot debian/rules binary-headers binary-${FLAVOUR} \
	       	${BUILD_TOOL_STR} do_zfs=false do_mstflint_access=false do_nvidia-fs=false do_skip_checks=true; \
		echo \$? > build_lock" 2>&1 | tee build.log_arm64
else
        echo "Not supported ${ARCH}"
        exit 127
fi

if [ $(eval cat build_lock) != "0" ]; then
        echo "Built error arch=${ARCH}"
	false
else
	true
fi 