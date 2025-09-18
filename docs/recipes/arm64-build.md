Title: Building for generic ARM64 device

# Building Vanetza for generic ARM64 device

This document describes building Vanetza for arm64 architecture.
Steps for building Vanetza for arm64 are very similar to build for Cohda MK5 devices (you can see steps in the [building for Cohda MK5 document](cohda-sdk-build.md)).

## Cross-compiler

You should have GNU C/C++ cross-compiler for the arm64 architecture installed. For Debian-based distros, this can be installed by command `sudo apt install g++-aarch64-linux-gnu`.

## Vanetza build dependencies

Please see [this document](cross-compile-dependencies.md) about cross-compiling Vanetza's dependencies.

## Compile Vanetza

We assume you have copy of the Vanetza repository in your home directory at `$HOME`.
Create a build directory and tell CMake to use the cross-compiler installed on your machine and to look up additional dependencies in `vanetza-deps`:

    :::shell
    mkdir vanetza/vanetza-build
    cd vanetza/vanetza-build
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE=../cmake/Toolchain-ARM64.cmake \
        -DCMAKE_FIND_ROOT_PATH=$HOME/vanetza-deps \
        -DCMAKE_INSTALL_RPATH=\$ORIGIN/../lib \
        -DCMAKE_INSTALL_PREFIX=$HOME/vanetza-dist \
        -DBUILD_SOCKTAP=ON
    make

This builds the Vanetza libraries and *socktap* example as well. When you do `make install`, binaries are copied to `$HOME/vanetza-dist`. You can copy the binary with libraries to the device now.

