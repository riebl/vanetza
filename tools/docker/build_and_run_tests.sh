#!/bin/bash
set -e
ROOT=${1:?missing Vanetza root directory}
ROOT_PATH=$(readlink -f ${ROOT})

mkdir build && cd build
cmake -DBUILD_TESTS=ON ${ROOT_PATH}
cmake --build .
ctest
