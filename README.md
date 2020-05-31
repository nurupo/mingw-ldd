# mingw-ldd

Tool to list dependencies of a PE (exe/dll) file.

## Features

- Tries to mimic ldd-like output
- Allows to specify dll lookup paths, there are no hardcoded paths
- Makes sure the dependencies are of the same CPU architecture
- Sorts the output by dll name
- Can also print per-dep or tree outputs

Note that the arguments do not mimic ldd arguments.

## Usage

### Install dependencies


```sh
sudo apt-get install python3-pefile
```

or

```sh
sudo apt-get install virtualenv
virtualenv -p /usr/bin/python3 env
./env/bin/pip install -r requirements.txt
```

### Use

```sh
$ mingw-ldd.py -h
usage: mingw-ldd.py [-h] [--output-format {ldd-like,per-pe-list,tree}] --dll-lookup-dirs DLL_LOOKUP_DIR [DLL_LOOKUP_DIR ...] PE_FILE

# Intentionally using 64-bit system32 to show off "not found" in these examples

# ldd-like output
$ ./mingw-ldd.py /home/nurupo/qtox/workspace/i686/qtox/release/libtoxcore.dll \
                 --dll-lookup-dirs /usr/lib/gcc/i686-w64-mingw32/*-posix \
                                   /usr/i686-w64-mingw32/lib \
                                   /home/nurupo/.wine/drive_c/windows/system32 \
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

# per-pe-list output
$ ./mingw-ldd.py /home/nurupo/qtox/workspace/i686/qtox/release/libtoxcore.dll \
                 --output-format per-pe-list \
                 --dll-lookup-dirs /usr/lib/gcc/i686-w64-mingw32/*-posix \
                                   /usr/i686-w64-mingw32/lib \
                                   /home/nurupo/.wine/drive_c/windows/system32 \
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

# tree output
$ ./mingw-ldd.py /home/nurupo/qtox/workspace/i686/qtox/release/libtoxcore.dll \
                 --output-format tree \
                 --dll-lookup-dirs /usr/lib/gcc/i686-w64-mingw32/*-posix \
                                   /usr/i686-w64-mingw32/lib \
                                   /home/nurupo/.wine/drive_c/windows/system32 \
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

## Disclaimer

This project is not affiliated with MinGW, the name "mingw-ldd" is used primarely to facilitate online search discoverability as MinGW suit is missing ldd.


## License

MIT
