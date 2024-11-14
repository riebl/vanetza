#!/bin/bash
set -eu

if [[ ! -d "/AFLplusplus" ]] ; then
    echo "This script shall be run inside the AFL++ container"
    exit 1
fi

cd /home/fuzz

export CC=${CC:=afl-clang-lto}
export CXX=${CXX:=afl-clang-lto++}

export AFL_LLVM_CMPLOG=1
mkdir -p build/cmplog
cmake -S source -B build/cmplog -G Ninja -DBUILD_FUZZ=ON
cmake --build build/cmplog
unset AFL_LLVM_CMPLOG

# see https://aflplus.plus/docs/env_variables/ for supported environment variables
export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1
mkdir -p build/asan
cmake -S source -B build/asan -G Ninja -DBUILD_FUZZ=ON
cmake --build build/asan
