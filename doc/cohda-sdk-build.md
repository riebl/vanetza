# Building Vanetza for Cohda MK5 using Cohda SDK

This document describes step-by-step how to build Vanetza using the Cohda SDK.
At the end, we have Vanetza libraries and its *socktap* tool cross-compiled for Cohda MK5 devices.


## Cohda SDK

[Cohda SDK](http://www.cohdawireless.com/solutions/sdk/) is provided by [Cohda Wireless](http://www.cohdawireless.com) along with their [MK5](http://www.cohdawireless.com/solutions/hardware/mk5-obu/) units.
Since you are reading this build how-to you most likely already possess one of these units.
This how-to has been created for the Release 16 of the SDK.
The following instructions are expected to be done within the virtual machine (VM) provided by Cohda.


## Vanetza build dependencies

Compilation of Vanetza depends on several third-party libraries, e.g. Boost, GeographicLib and Crypto++ as mentioned in Vanetza's README.
For the sake of simplicity, we provide the pre-compiled dependencies for Cohda MK5 as compressed archive.
This archive contains *Boost 1.65.1*, *GeographicLib 1.49* and *Crypto++ 5.6.5*.
The archive can be downloaded from [box.com](https://app.box.com/s/zu0q7i569xsuu0qno378axwnf5w5v3op).
MD5 checksum of *vanetza-deps-20171129.tar.bz2* is `853a2833fde0266674d4a4dbe22fe7ef`.
Extract the archive's content into `/home/duser/vanetza-deps`.


## Compile Vanetza

We assume you have copy of the Vanetza repository in your home directory at `/home/duser/vanetza`.
Create a build directory and tell CMake to use the cross-compiler installed in the Cohda VM and to look up additional dependencies in `vanetza-deps`:

    mkdir vanetza-build
    cd vanetza-build
    cmake $HOME/vanetza \
        -DCMAKE_TOOLCHAIN_FILE=$HOME/vanetza/cmake/Toolchain-Cohda-MK5.cmake \
        -DCMAKE_FIND_ROOT_PATH=$HOME/vanetza-deps \
        -DCMAKE_EXE_LINKER_FLAGS=-pthread \
        -DCMAKE_INSTALL_RPATH=\$ORIGIN/../lib \
        -DCMAKE_INSTALL_PREFIX=$HOME/vanetza-dist
    make

This builds the Vanetza libraries only. Enable the **BUILD_SOCKTAP** CMake option if you want to try *socktap* as well. Additionally, enable the **SOCKTAP_WITH_COHDA_LLC** CMake option if you want *socktap* to use 802.11p via Cohda's LLC network interface on your MK5.
Fortunately, *socktap*'s additional *gpsd* dependency is already shipped with the Cohda SDK itself.
You only need to specify its location by setting **GPS_LIBRARY** to `/home/duser/mk5/stack/v2x-lib/lib/mk5/libgps.a` and **GPS_INCLUDE_DIR** to `/home/duser/mk5/stack/v2x-lib/include`.
Please note, that *socktap* does not make use of Cohda's socket API currently.
We might provide a modified *socktap* application in the future.


## Deployment

1. `make install`

Compile and link *socktap* with correct RPATH, binaries are copied to `$HOME/vanetza-dist`.

2. copy runtime dependencies

Copy the shared object files (*.so) from `$HOME/vanetza-deps/libs` onto the MK5, e.g. to `/home/duser/vanetza/lib`.

3. copy *socktap* onto MK5

Copy the files from `$HOME/vanetza-dist` to `/home/duser/vanetza` on the MK5, i.e. Vanetza libraries and its dependency libraries are located in the same directory.
You can execute *socktap* located at `/home/duser/vanetza/bin/socktap` and it will look up its shared objects in the sibling `lib` directory. If you have enabled the **SOCKTAP_WITH_COHDA_LLC** CMake option, make sure to give *socktap* the name of a Cohda LLC network interface via the command line option `--interface`/`-i` (e.g. cw-llc0).
