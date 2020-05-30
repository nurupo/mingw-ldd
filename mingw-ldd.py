#!/usr/bin/env python

# MIT License
#
# Copyright (c) 2020 Maxim Biro <nurupo.contributions@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import argparse
import os
import pefile
import sys

def find_file_ignore_case(dirname, filename):
    (root, _, filenames) = next(os.walk(dirname))
    filename_lower = filename.lower()
    for f in filenames:
        if f.lower() == filename_lower:
            return os.path.join(root, f)
    return None


def get_dependency(filename):
    deps = []
    pe = pefile.PE(filename)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for imp in pe.DIRECTORY_ENTRY_IMPORT:
            deps.append(imp.dll.decode())
    return deps


def dep_tree(pe, dll_lookup_dirs):
    dlls = {}
    arch = pefile.PE(pe).FILE_HEADER.Machine

    def dep_tree_impl(pe):
        for dll in get_dependency(pe):
            dll_lower = dll.lower()
            if dll_lower in dlls:
                continue
            dlls[dll_lower] = 'not found'
            for dir in dll_lookup_dirs:
                dll_path = find_file_ignore_case(dir, dll)
                if dll_path and pefile.PE(dll_path).FILE_HEADER.Machine == arch:
                    dlls[dll_lower] = dll_path
                    dep_tree_impl(dll_path)

    dep_tree_impl(pe)
    return dlls


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ldd-like program for PE files')
    parser.add_argument('--output-format', type=str, choices=('ldd-like', 'per-dep-list', 'tree'), default='ldd-like')
    parser.add_argument('--dll-lookup-dirs', metavar='DLL_LOOKUP_DIR', type=str, default=[], nargs='+', required=True)
    parser.add_argument('pe_file', metavar='PE_FILE')
    args = parser.parse_args()
    dll_lookup_dirs = [os.path.abspath(dir) for dir in args.dll_lookup_dirs]
    for dir in dll_lookup_dirs:
        if not os.path.isdir(dir):
            sys.exit('Error: "{}" directory doesn\'t exist.'.format(dir))
    if args.output_format != 'ldd-like':
        sys.exit('Error: Output format {} is not supported yet.'.format(args.output_format))
    deps = dep_tree(args.pe_file, dll_lookup_dirs)
    for dll, dll_path in sorted(deps.items()):
        print(' ' * 7, dll, '=>', dll_path)

