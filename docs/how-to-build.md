# How to build

Building Vanetza is accomplished by the [CMake](https://cmake.org) build system. Hence, CMake needs to be available on the build host.

## Prerequisites

You need following tools and libraries on your system for compiling Vanetza:

* C++11 compatible compiler, e.g. [GNU GCC](https://gcc.gnu.org) or [Clang](http://clang.llvm.org)
* [CMake](https://cmake.org) 3.1 or higher
* [Boost](https://www.boost.org) 1.58 or higher
* [GeographicLib](http://geographiclib.sourceforge.net) 1.37 or higher
* [Crypto++](https://www.cryptopp.com) 5.6.1 or higher

If OpenSSL (1.0 or 1.1) or LibreSSL is available on your system, an alternative security backend implementation is compiled along with the Crypto++ based backend.
See `security::Backend` and `security::create_backend` for more details.


## Compilation

Following command line snippet demonstrates the build process using a generated Makefile.
Other CMake generators and build directory setups can be used as well.

    :::shell
    cd vanetza
    mkdir build && cd build
    cmake ..
    make


## Unit tests

Vanetza comes with many unit tests covering the most critical parts.
When the CMake option `BUILD_TESTS` is enabled, the [Google Test](https://github.com/google/googletest/) sources are downloaded by the build system automatically.
The built test cases are standalone executables located in the *tests* subdirectory of your build directory.
For running all test cases, I recommend to invoke `ctest` in your build directory.


## Integrating Vanetza

Vanetza is primarily a library project intended for integration by other projects, e.g. V2X simulation tools such as [Artery](https://github.com/riebl/artery).
Projects using CMake can integrate Vanetza most easily by calling `find_package(Vanetza)` and then refer to the imported Vanetza targets, such as `Vanetza::vanetza`.

