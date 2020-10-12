#!/usr/bin/env bash

# Simple smoke test to make sure mingw-dll doesn't crash

set -exo pipefail

# Try both arches
__MINGW_TEST()
{
  "$@"
  "${@//i686/x86_64}"
}

# Try all output formats
_MINGW_TEST()
{
  __MINGW_TEST "$@"
  __MINGW_TEST "$@" --output-format ldd-like
  __MINGW_TEST "$@" --output-format per-dep-list
  __MINGW_TEST "$@" --output-format tree
}

# Try all invocation methods
MINGW_TEST()
{
  _MINGW_TEST mingw-ldd "$@"
  _MINGW_TEST python3 -m mingw_ldd "$@"
  _MINGW_TEST python3 mingw_ldd/mingw_ldd.py "$@"
}

# MinGW tests should use i686 arch without output formatting specified

MINGW_TEST /usr/lib/gcc/i686-w64-mingw32/*-posix/libgomp-1*.dll \
           --dll-lookup-dirs /usr/lib/gcc/i686-w64-mingw32/*-posix \
                             /usr/i686-w64-mingw32/lib

# Test tree output recursion
# Note that Wine changes dll deps often, so this test might fail if they remove
# the cyclic dependency
mingw-ldd ~/.wine/drive_c/windows/system32/avifil32.dll \
          --dll-lookup-dirs ~/.wine/drive_c/windows/system32 \
          --output-format tree | grep 'recursion'
