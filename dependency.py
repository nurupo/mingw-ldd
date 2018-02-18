#!/usr/bin/env python3
# WTFPL – Do What the Fuck You Want to Public License
import subprocess
import os
import sys

prefixes = {
    'i386': '/usr/i686-w64-mingw32/bin',
    'AMD64': '/usr/x86_64-w64-mingw32/bin'
}


def search_line(command, needle, callback):
    output = subprocess.check_output(command)
    ret = None
    for line in output.splitlines():
        line_ = line.decode('utf-8')
        if needle not in line_:
            continue
        ret = callback(line_)
    return ret


def get_dependency(filename):
    deps = []

    def _add_dep(line):
        deps.append(line.strip().split(' ')[2])

    search_line(['winedump', '-j', 'import', filename], 'offset', _add_dep)
    return deps


def dep_tree(root, prefix=None):
    if not prefix:
        arch = get_arch(root)
        if arch not in prefixes:
            sys.stderr.write('Error: unknown architecture %s\n' % arch)
            sys.exit(1)
        print('Arch =', arch)
        prefix = prefixes[arch]
        print('Using default prefix', prefix)
    dep_dlls = []
    not_found = []

    def dep_tree_impl(root, prefix):
        for dll in get_dependency(root):
            full_path = os.path.join(prefix, dll)
            if not os.path.exists(full_path):
                if dll not in not_found:
                    not_found.append(dll)
                continue
            if full_path not in dep_dlls:
                dep_dlls.append(full_path)
            dep_tree_impl(full_path, prefix=prefix)

    dep_tree_impl(root, prefix)
    return (dep_dlls, not_found)


def get_arch(filename):
    def _handle_line(line):
        # (arch) is the last item. Use [1:-1] to get rid of parentheses
        return line.strip().split(' ')[-1][1:-1]
    return search_line(['winedump', 'dump', '-f', filename],
                       'Machine:', _handle_line)


if __name__ == '__main__':
    filename = sys.argv[1]
    deps, not_found = dep_tree(filename)
    print('\n'.join(deps))
    print('The following dependencies not found: ')
    print('\n'.join(not_found))