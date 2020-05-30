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

from __future__ import print_function
import pefile
import os
import sys


def get_dependency(filename):
    deps = []
    pe = pefile.PE(filename)
    for imp in pe.DIRECTORY_ENTRY_IMPORT:
        deps.append(imp.dll.decode())
    return deps


def dep_tree(root, prefix=None):
    if not prefix:
        arch = get_arch(root)
        #print('Arch =', arch)
        prefix = '/usr/'+arch+'-w64-mingw32/bin'
        #print('Using default prefix', prefix)
    dep_dlls = dict()

    def dep_tree_impl(root, prefix):
        for dll in get_dependency(root):
            if dll in dep_dlls:
                continue
            full_path = os.path.join(prefix, dll)
            if os.path.exists(full_path):
                dep_dlls[dll] = full_path
                dep_tree_impl(full_path, prefix=prefix)
            else:
                dep_dlls[dll] = 'not found'

    dep_tree_impl(root, prefix)
    return (dep_dlls)


def get_arch(filename):
    type2arch= {pefile.OPTIONAL_HEADER_MAGIC_PE: 'i686',
                pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS: 'x86_64'}
    pe = pefile.PE(filename)
    try:
        return type2arch[pe.PE_TYPE]
    except KeyError:
        sys.stderr.write('Error: unknown architecture')
        sys.exit(1)

if __name__ == '__main__':
    filename = sys.argv[1]
    for dll, full_path in dep_tree(filename).items():
        print(' ' * 7, dll, '=>', full_path)

