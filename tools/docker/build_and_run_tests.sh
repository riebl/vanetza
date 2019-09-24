#!/bin/bash
set -e
SCRIPT=$(readlink -f $0)
SCRIPT_PATH=$(dirname $SCRIPT)
ROOT=${1:-$SCRIPT_PATH/../..}
ROOT_PATH=$(readlink -f ${ROOT})

mkdir -p build && cd build
cmake -DBUILD_TESTS=ON ${ROOT_PATH}
cmake --build .
ctest
