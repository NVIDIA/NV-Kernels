#!/bin/bash
set -euo pipefail

expected_arch=${1:?Expected architecture is required}
expected_pagesize=${2:?Expected page size is required}
expected_release=${3-}
actual_arch=$(uname -m)
actual_pagesize=$(getconf PAGESIZE)

uname -a
printf 'Architecture: expected=%s actual=%s\n' "$expected_arch" "$actual_arch"
printf 'Page size: expected=%s actual=%s\n' "$expected_pagesize" "$actual_pagesize"
test "$actual_arch" = "$expected_arch"
test "$actual_pagesize" = "$expected_pagesize"
if [ -n "$expected_release" ]; then
    actual_release=$(uname -r)
    printf 'Kernel release: expected=%s actual=%s\n' "$expected_release" "$actual_release"
    test "$actual_release" = "$expected_release"
fi
