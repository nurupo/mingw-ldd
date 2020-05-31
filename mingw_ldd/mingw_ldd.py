#!/usr/bin/env python
# -*- coding: utf-8 -*-

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


def get_dependency(pe_data):
    deps = []
    if hasattr(pe_data, 'DIRECTORY_ENTRY_IMPORT'):
        for imp in pe_data.DIRECTORY_ENTRY_IMPORT:
            deps.append(imp.dll.decode())
    return deps


def dep_tree(pe, dll_lookup_dirs):
    dlls = {}
    deps = {}
    dlls_blacklist = []
    pe_data = pefile.PE(pe)
    arch = pe_data.FILE_HEADER.Machine

    def dep_tree_impl(pe, pe_data):
        pe = os.path.abspath(pe)
        if pe in deps:
            return
        deps[pe] = []
        for dll in get_dependency(pe_data):
            dll_lower = dll.lower()
            if dll_lower in dlls:
                deps[pe].append(dll)
                continue
            dlls[dll_lower] = 'not found'
            for dir in dll_lookup_dirs:
                dll_path = find_file_ignore_case(dir, dll)
                if not dll_path or dll_path in dlls_blacklist:
                    continue
                new_pe_data = pefile.PE(dll_path)
                if new_pe_data.FILE_HEADER.Machine == arch:
                    dlls[dll_lower] = dll_path
                    dep_tree_impl(dll_path, new_pe_data)
                    break
                else:
                    dlls_blacklist.append(dll_path)
            deps[pe].append(dll)

    dep_tree_impl(pe, pe_data)
    return (dlls, deps)


def main():
    try:
        from .__version__ import __description__, __version__
    except:
        parser = argparse.ArgumentParser()
    else:
        parser = argparse.ArgumentParser(description=__description__)
        parser.add_argument('--version', action='version', version='{}'.format(__version__))
    parser.add_argument('--output-format', type=str, choices=('ldd-like', 'per-dep-list', 'tree'), default='ldd-like')
    parser.add_argument('--dll-lookup-dirs', metavar='DLL_LOOKUP_DIR', type=str, default=[], nargs='+', required=True)
    parser.add_argument('pe_file', metavar='PE_FILE')
    args = parser.parse_args()
    dll_lookup_dirs = [os.path.abspath(dir) for dir in args.dll_lookup_dirs]
    for dir in dll_lookup_dirs:
        if not os.path.isdir(dir):
            sys.exit('Error: "{}" directory doesn\'t exist.'.format(dir))
    (dlls, deps) = dep_tree(args.pe_file, dll_lookup_dirs)
    if args.output_format == 'ldd-like':
        for dll, dll_path in sorted(dlls.items(), key=lambda e: e[0].casefold()):
            print(' ' * 7, dll, '=>', dll_path)
    elif args.output_format == 'per-dep-list':
        for pe, dll_names in sorted(deps.items(), key=lambda e: e[0].casefold()):
            print(pe)
            for dll in sorted(dll_names, key=str.casefold):
                dll_path = dlls[dll.lower()]
                print(' ' * 7, dll, '=>', dll_path)
    elif args.output_format == 'tree':
        def print_tree(pe, level=0, prefix=''):
            if level == 0:
                print(pe)
                print_tree(pe, 1, '')
                return
            if pe == 'not found':
                return
            count = 0
            for dll in sorted(deps[pe], key=str.casefold):
                dll_path = dlls[dll.lower()]
                count += 1
                is_last_dll = count == len(deps[pe])
                new_prefix = '{}{}'.format(prefix, '    ' if is_last_dll else '│   ')
                print('{}{} {} => {}'.format(prefix, '└──' if is_last_dll else '├──', dll, dll_path))
                print_tree(dll_path, level+1, new_prefix)
        print_tree(os.path.abspath(args.pe_file))

if __name__ == '__main__':
    main()
