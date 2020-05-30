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

import pefile
import os
import sys

def find_file_ignore_case(filepath):
    (root, _, filenames) = next(os.walk(os.path.dirname(filepath)))
    filename = os.path.basename(filepath).lower()
    for f in filenames:
        if f.lower() == filename:
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

    def dep_tree_impl(pe):
        for dll in get_dependency(pe):
            dll_lower = dll.lower()
            if dll_lower in dlls:
                continue
            dlls[dll_lower] = 'not found'
            for dir in dll_lookup_dirs:
                full_path = find_file_ignore_case(os.path.join(dir, dll))
                if full_path:
                    dlls[dll_lower] = full_path
                    dep_tree_impl(full_path)

    dep_tree_impl(pe)
    return dlls


if __name__ == '__main__':
    if len(sys.argv) < 3:
        sys.exit("Usage: {} PE_FILE DLL_LOOKUP_DIR [DLL_LOOKUP_DIR ...]".format(sys.argv[0]))
    pe = sys.argv[1]
    dll_lookup_dirs = [os.path.abspath(dir) for dir in sys.argv[2:]]
    for dir in dll_lookup_dirs:
        if not os.path.isdir(dir):
            sys.exit('Error: "{}" directory doesn\'t exist.'.format(p))
    for dll, full_path in dep_tree(pe, dll_lookup_dirs).items():
        print(' ' * 7, dll, '=>', full_path)

