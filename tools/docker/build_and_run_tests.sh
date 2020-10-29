#!/bin/bash
set -e
SCRIPT=$(readlink -f $0)
SCRIPT_PATH=$(dirname $SCRIPT)
ROOT=${1:-$SCRIPT_PATH/../..}
ROOT_PATH=$(readlink -f ${ROOT})
BUILD_DIR=${BUILD_DIR:-$PWD/build}

mkdir -p ${BUILD_DIR} && cd ${BUILD_DIR}
cmake -DBUILD_TESTS=ON -DGTest_BUILD_DIRECTORY_DOWNLOAD=ON ${ROOT_PATH}
cmake --build .
ctest
