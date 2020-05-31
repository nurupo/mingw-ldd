#!/usr/bin/env bash

# Simple smoke test to make sure mingw-dll doesn't crash

set -exo pipefail

# Try both arches
__TEST()
{
  "$@"
  "${@//i686/x86_64}"
}

# Try all output formats
_TEST()
{
  __TEST "$@"
  __TEST "$@" --output-format ldd-like
  __TEST "$@" --output-format per-dep-list
  __TEST "$@" --output-format tree
}

# Try all invocation methods
TEST()
{
  _TEST mingw-ldd "$@"
  _TEST python3 -m mingw_ldd "$@"
  _TEST python3 mingw_ldd/mingw_ldd.py "$@"
}

# Tests should use i686 arch without output formatting specified

TEST /usr/lib/gcc/i686-w64-mingw32/*-posix/libgomp-1*.dll \
     --dll-lookup-dirs /usr/lib/gcc/i686-w64-mingw32/*-posix \
                       /usr/i686-w64-mingw32/lib

