Title: Building for Autotalks devices

# Building Vanetza for Autotalks Craton using Autotalks SDK

This document describes building Vanetza for the Autotalks device. There is a difference between building for Craton and Secton.
Steps for building Vanetza for Autotalks Craton are very similar to build for Cohda MK5 devices (you can see steps in the [building for Cohda MK5 document](cohda-sdk-build.md)). Difference is that there is no virtual machine provided from Autotalks.

Autotalks SDK can used only in the `socktap` example, so you must always compile it when you want the SDK.

## Autotalks SDK

SDK is shipped with Autotalks devices, you should have obtained one. Until Release 18, it was recommended to build the SDK in Ubuntu 16.04, now Ubuntu 18.04 or 20.04 should be used; it was tested on the latter. For Secton, there is used gcc version 9.4.0, for Craton `arm-poky-linux-gnueabi-g++` version 11.2.0, that is installed with the poky container.

### Code corrections

With Autotalks SDK version <= 5.15.0, you will have to do a correction in file `autotalks_*_api/include/atlk/ddm_service.h` on line 615 and add there an explicit cast to `stats_tlv_t *`. Without this, you won't be able to build the project because of the `-fpermissive` flag. As of version 5.16.0, this problem is fixed.

In version 5.17 (Release 18), there are another problems:
* In autotalks_{craton,secton}_api/include/common/counters.h change line 110 from `uint8_t data[]` to `uint8_t* data`
* In autotalks_{craton,secton}_api/include/atlk/generic_compensator.h, there is missing `}` for the `extern "C"` directive (this should be solved in newer SDK)

Another thing you must note is in the initialization in the `socktap` example. The initialization code in `v2x_device_init()` was used directly from the example in the Autotalks SDK, therefore it should not be distributed with the library. You will have to write it yourself, but it really is almost the same as `main()` function in the basic example from the SDK.

In the initialization, there is a define for `SECTON_NET_NAME`. This is a network interface name which determines how is the SoC seen in Linux. It should be *enx0002ccf00006* by default, but if it is set to something else, you can change this define. You can use `ifconfig` output to determine the actual name (see Autotalks documentation for more details).

## Vanetza build dependencies

Please see [this document](cross-compile-dependencies.md) about cross-compiling Vanetza's dependencies.
This guide  was tested with precompiled libraries downloadable [from here](cohda-sdk-build.md).

## Compile Vanetza

### Compiling for Craton
We assume you have copy of the Vanetza repository in your home directory at `$HOME`.
Furthermore, there should be a symbolic link named `autotalks_craton_api` in your home directory, that links to the root of Craton SDK (e.g., from `/home/your_user/autotalks_craton_api` to the API compilation directory). If you have Poky toolchain installed in other directory than /opt/poky-craton2/4.0.1 (e.g. /tools/gcc/arm/new_toolchain as suggested by Autotalks), change the path in cmake/Toolchain-Autotalks-Craton.cmake.
Create a build directory and tell CMake to use the cross-compiler installed on your machine and to look up additional dependencies in `vanetza-deps`:

    :::shell
    mkdir vanetza/vanetza-build
    cd vanetza/vanetza-build
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE=../cmake/Toolchain-Autotalks-Craton.cmake \
        -DCMAKE_FIND_ROOT_PATH=$HOME/vanetza-deps \
        -DCMAKE_INSTALL_RPATH=\$ORIGIN/../lib \
        -DCMAKE_INSTALL_PREFIX=$HOME/vanetza-dist \
        -DBUILD_SOCKTAP=ON \
        -DSOCKTAP_WITH_AUTOTALKS=ON
    make

This builds the Vanetza libraries and *socktap* example as well. When you do `make install`, binaries are copied to `$HOME/vanetza-dist`. You can copy the binary with libraries to the Craton now. You should start the binary in the same directory as you would be running code from Autotalks examples (it needs their configuration files). You must run the binary with parameter `-l autotalks` for correct choosing of the link layer.

### Compiling for Secton
We assume you have copy of the Vanetza repository in your home directory at `$HOME`.
Furthermore, there should be a symbolic link named `autotalks_secton_api` in your home directory, that links to the root of Secton SDK (e.g., from `/home/your_user/autotalks_secton_api` to the API compilation directory). The build steps are then identical with the ones described in [How to build](../how-to-build.md). Just note that for using Autotalks SDK you should use enable compilation of socktap, e.g. like this:

    :::shell
    cmake .. \
        -DBUILD_SOCKTAP=ON \
        -DSOCKTAP_WITH_AUTOTALKS=ON
    make

Binary then can be ran from the same directory you would be running the Autotalks example (it needs their configuration files). You must run the binary with parameter `-l autotalks` for correct choosing of the link layer.

