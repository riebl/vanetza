#!/bin/bash
set -e
SCRIPT=$(readlink -f $0)
SCRIPT_PATH=$(dirname $SCRIPT)
ROOT=${1:-$SCRIPT_PATH/../..}
ROOT_PATH=$(readlink -f ${ROOT})
BUILD_DIR=${BUILD_DIR:-$PWD/build}

mkdir -p ${BUILD_DIR} && cd ${BUILD_DIR}
cmake -G Ninja \
    -DBUILD_CERTIFY=ON -DBUILD_SOCKTAP=ON \
    -DBUILD_TESTS=ON  -DGTest_BUILD_DIRECTORY_DOWNLOAD=ON \
    ${ROOT_PATH}
cmake --build .
ctest --output-on-failure
