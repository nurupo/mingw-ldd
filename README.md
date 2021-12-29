# mingw-ldd

Lists dependencies of a PE (exe/dll) file.


## Features

- Mimics ldd output
- Allows to specify dll lookup paths
- Has no hardcoded dll lookup paths
- Makes sure the dependencies are of the same CPU architecture
- Sorts the output by dll name
- Can also print in per-dep or tree output formats
- Uses multiprocessing to speed up the dll lookup

Note that the arguments do not mimic ldd arguments.


## Usage

The script can be installed from PyPi:

```sh
pip install mingw_ldd
mingw-ldd --help
```

The script can be used stanalone, given you have `pefile` installed:

```sh
sudo apt-get install python3-pefile
./mingw_ldd/mingw_ldd.py --help
```

or:

```sh
sudo apt-get install virtualenv
virtualenv -p /usr/bin/python3 env
./env/bin/pip install -r requirements.txt
./env/bin/python3 ./mingw_ldd/mingw_ldd.py --help
```

The `mingw_ldd.py` script file is self-contained and can be easily copied into other project's codebase.


## Example

```sh
$ mingw-ldd.py -h
usage: mingw_ldd.py [-h] [--output-format {ldd-like,per-dep-list,tree}] --dll-lookup-dirs DLL_LOOKUP_DIR [DLL_LOOKUP_DIR ...] [--disable-multiprocessing] PE_FILE
```

Ldd-like output:

```sh
$ ./mingw-ldd.py /home/nurupo/qtox/workspace/i686/qtox/release/libtoxcore.dll \
                 --dll-lookup-dirs /usr/lib/gcc/i686-w64-mingw32/*-posix \
                                   /usr/i686-w64-mingw32/lib \
                                   /home/nurupo/qtox/workspace/i686/qtox/release
        advapi32.dll => not found
        iphlpapi.dll => not found
        kernel32.dll => not found
        libgcc_s_sjlj-1.dll => /usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
        libopus-0.dll => /home/nurupo/qtox/workspace/i686/qtox/release/libopus-0.dll
        libsodium-23.dll => /home/nurupo/qtox/workspace/i686/qtox/release/libsodium-23.dll
        libvpx.dll => /home/nurupo/qtox/workspace/i686/qtox/release/libvpx.dll
        libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
        msvcrt.dll => not found
        user32.dll => not found
        ws2_32.dll => not found
```

Per-dep-list output:

```sh
$ ./mingw-ldd.py /home/nurupo/qtox/workspace/i686/qtox/release/libtoxcore.dll \
                 --output-format per-dep-list \
                 --dll-lookup-dirs /usr/lib/gcc/i686-w64-mingw32/*-posix \
                                   /usr/i686-w64-mingw32/lib \
                                   /home/nurupo/qtox/workspace/i686/qtox/release
/home/nurupo/qtox/workspace/i686/qtox/release/libopus-0.dll
        KERNEL32.dll => not found
        libgcc_s_sjlj-1.dll => /usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
        msvcrt.dll => not found
/home/nurupo/qtox/workspace/i686/qtox/release/libsodium-23.dll
        ADVAPI32.dll => not found
        KERNEL32.dll => not found
        libgcc_s_sjlj-1.dll => /usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
        msvcrt.dll => not found
        USER32.dll => not found
/home/nurupo/qtox/workspace/i686/qtox/release/libtoxcore.dll
        IPHLPAPI.DLL => not found
        KERNEL32.dll => not found
        libgcc_s_sjlj-1.dll => /usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
        libopus-0.dll => /home/nurupo/qtox/workspace/i686/qtox/release/libopus-0.dll
        libsodium-23.dll => /home/nurupo/qtox/workspace/i686/qtox/release/libsodium-23.dll
        libvpx.dll => /home/nurupo/qtox/workspace/i686/qtox/release/libvpx.dll
        libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
        msvcrt.dll => not found
        WS2_32.dll => not found
/home/nurupo/qtox/workspace/i686/qtox/release/libvpx.dll
        KERNEL32.dll => not found
        libgcc_s_sjlj-1.dll => /usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
        libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
        msvcrt.dll => not found
/usr/i686-w64-mingw32/lib/libwinpthread-1.dll
        KERNEL32.dll => not found
        msvcrt.dll => not found
/usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
        KERNEL32.dll => not found
        libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
        msvcrt.dll => not found
```


Tree output:

```sh
$ ./mingw-ldd.py /home/nurupo/qtox/workspace/i686/qtox/release/libtoxcore.dll \
                 --output-format tree \
                 --dll-lookup-dirs /usr/lib/gcc/i686-w64-mingw32/*-posix \
                                   /usr/i686-w64-mingw32/lib \
                                   /home/nurupo/qtox/workspace/i686/qtox/release
/home/nurupo/qtox/workspace/i686/qtox/release/libtoxcore.dll
├── IPHLPAPI.DLL => not found
├── KERNEL32.dll => not found
├── libgcc_s_sjlj-1.dll => /usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
│   ├── KERNEL32.dll => not found
│   ├── libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
│   │   ├── KERNEL32.dll => not found
│   │   └── msvcrt.dll => not found
│   └── msvcrt.dll => not found
├── libopus-0.dll => /home/nurupo/qtox/workspace/i686/qtox/release/libopus-0.dll
│   ├── KERNEL32.dll => not found
│   ├── libgcc_s_sjlj-1.dll => /usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
│   │   ├── KERNEL32.dll => not found
│   │   ├── libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
│   │   │   ├── KERNEL32.dll => not found
│   │   │   └── msvcrt.dll => not found
│   │   └── msvcrt.dll => not found
│   └── msvcrt.dll => not found
├── libsodium-23.dll => /home/nurupo/qtox/workspace/i686/qtox/release/libsodium-23.dll
│   ├── ADVAPI32.dll => not found
│   ├── KERNEL32.dll => not found
│   ├── libgcc_s_sjlj-1.dll => /usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
│   │   ├── KERNEL32.dll => not found
│   │   ├── libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
│   │   │   ├── KERNEL32.dll => not found
│   │   │   └── msvcrt.dll => not found
│   │   └── msvcrt.dll => not found
│   ├── msvcrt.dll => not found
│   └── USER32.dll => not found
├── libvpx.dll => /home/nurupo/qtox/workspace/i686/qtox/release/libvpx.dll
│   ├── KERNEL32.dll => not found
│   ├── libgcc_s_sjlj-1.dll => /usr/lib/gcc/i686-w64-mingw32/9.3-posix/libgcc_s_sjlj-1.dll
│   │   ├── KERNEL32.dll => not found
│   │   ├── libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
│   │   │   ├── KERNEL32.dll => not found
│   │   │   └── msvcrt.dll => not found
│   │   └── msvcrt.dll => not found
│   ├── libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
│   │   ├── KERNEL32.dll => not found
│   │   └── msvcrt.dll => not found
│   └── msvcrt.dll => not found
├── libwinpthread-1.dll => /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
│   ├── KERNEL32.dll => not found
│   └── msvcrt.dll => not found
├── msvcrt.dll => not found
└── WS2_32.dll => not found
```


## Performance

The performance might be a bit slower than expected due to `pefile` sometimes taking up to few seconds to parse a dll.
We try to mitigate this by multiprocessing pefile's parsing.
Using the most up to date `pefile` should help too.
Specifically, the current version of `pefile` on PyPi -- version 2019.4.18, is noticeably faster than the version 2018.8.8 packaged in Debian Buster.

If the performance is an issue, you could give these projects a try:

- [ntldd](https://github.com/LRN/ntldd) - a cross-platform ldd-like program written in C
- [Dependency Walker](https://www.dependencywalker.com/) - a freeware Windows GUI application that displays PE dependencies


## Known issues

### API Set dlls

Dlls that start with `api-` and `ext-`, e.g. `api-ms-win-core-heap-l2-1-0.dll` or `ext-ms-win-ntuser-window-l1-1-1.dll`, might get incorrectly marked as "not found".

Such dlls are part of Windows's [API Set](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) feature.
The way the API Set works, is that often times the requested dlls don't even exist on the system, instead the library loader notices `api-*.dll` and `ext-*.dll` patterns and queries a mapping data-structure found in `ApiSetSchema.dll` to see which actual dlls those names map to and links those instead.
For example, linking to [`api-ms-win-core-heap-l2-1-0.dll`, in which one would expect to find the `LocalAlloc` function](https://docs.microsoft.com/en-us/uwp/win32-and-com/win32-apis#apis-from-api-ms-win-core-heap-l2-1-0dll), would [instead result in linking to `kernel32.dll`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc), and [`ext-ms-win-ntuser-window-l1-1-1.dll`, in which one would expect to find the `FindWindowEx` function, would instead link to `user32.dll`](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilea).

mingw-ldd scans directories for actual dll files, so since `api-` and `ext-` dlls might not exist, they could be just some table mappings to other dlls instead, mingw-ldd is unable to find them and thus reports "not found".
There is no public interface for applications to access this API Set dll mapping, the format of the mapping is not documented, and there are several reverse engineering articles attempting to document it, noting that `ApiSetSchema.dll` offsets change from architecture to architecture.

Because it's rather non-trivial and non-portable to access this mapping, mingw-ldd doesn't implement any API Set dll resolution.
It also doesn't affect my use-case of mingw-ldd, which is to see if a Windows binary I have built is missing any dll dependency before I zip it and package for users to download.
Because these API Set dlls are system libraries, you might just assume that they all are present.
It's non-system dlls missing that I'm more concerned about.

This doesn't mean that I don't want to see API Set dll resolution implemented.
Feel free to make a Python module parsing `ApiSetSchema.dll` that hides the portability details and I will make mingw-ldd use it.


## Disclaimer

This project is not affiliated with MinGW, the name "mingw-ldd" is used primarely to facilitate online search discoverability as MinGW suit is missing ldd.


## License

MIT
