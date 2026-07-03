#!/bin/bash
# Strict C++14 compile check for the Vanetza libraries.
set -e

SCRIPT=$(readlink -f "$0")
SCRIPT_PATH=$(dirname "$SCRIPT")
ROOT=${1:-$SCRIPT_PATH/../..}
ROOT_PATH=$(readlink -f "${ROOT}")
BUILD_DIR=${BUILD_DIR:-$PWD/build}

mkdir -p "${BUILD_DIR}" && cd "${BUILD_DIR}"
cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_CXX_STANDARD=14 \
    -DCMAKE_CXX_STANDARD_REQUIRED=ON \
    -DCMAKE_CXX_EXTENSIONS=OFF \
    -DVANETZA_WITH_CRYPTOPP=ON \
    -DVANETZA_WITH_OPENSSL=ON \
    -DVANETZA_WITH_GEOGRAPHICLIB=ON \
    -DVANETZA_WITH_RPC=OFF \
    -DBUILD_TESTS=OFF \
    "${ROOT_PATH}"
cmake --build .
