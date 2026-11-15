# How to build

Building Vanetza is accomplished by the [CMake](https://cmake.org) build system. Hence, CMake needs to be available on the build host.

## Prerequisites

You need following tools and libraries on your system for compiling Vanetza:

* C++14 compatible compiler, e.g. [GNU GCC](https://gcc.gnu.org) or [Clang](http://clang.llvm.org)
* [CMake](https://cmake.org) 3.18 or higher
* [Boost](https://www.boost.org) 1.70 or higher

Further libraries are optional: CMake enables a feature if its library is found, its option turns the feature on or off explicitly.

| Library | Version | CMake option | Feature |
|---|---|---|---|
| [GeographicLib](https://geographiclib.sourceforge.io) | 1.37 or higher | `VANETZA_WITH_GEOGRAPHICLIB` | precise geodesy |
| [Crypto++](https://www.cryptopp.com) | 5.6.1 or higher | `VANETZA_WITH_CRYPTOPP` | crypto provider and security module |
| [OpenSSL](https://www.openssl.org) | 1.1.1 or higher | `VANETZA_WITH_OPENSSL` | crypto provider and security module |
| [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto) or Mbed TLS | Mbed TLS 3.6 or higher | `VANETZA_WITH_PSA` | crypto provider and security module of the PSA Crypto API |
| [Cap'n Proto](https://capnproto.org) | 0.8 or higher | `VANETZA_WITH_RPC` | RPC support |
| [liboqs](https://openquantumsafe.org) | 0.14 or higher | `VANETZA_WITH_PQC` (off by default) | experimental hybrid-PQC certificate profile |

Secured messages require at least one crypto provider and security module, i.e. Crypto++, OpenSSL or the PSA Crypto API.
See `security::create_crypto_provider` and `security::create_security_module` for more details.
Persistence of key references, public keys and certificates (`VANETZA_WITH_PERSISTENCE`) is available if the compiler provides C++17's `std::filesystem`.

!!! hint
    If you are building on Ubuntu 16.04 or 18.04, please note that these Ubuntu releases ship outdated CMake versions unsuitable for Vanetza.
    Have a look at the [Kitware APT Repository](https://apt.kitware.com), which lists some of your options for installing an up-to-date CMake version.


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

