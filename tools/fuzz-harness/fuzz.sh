#!/bin/bash
set -eu
: ${FUZZ_INPUT:="$HOME/input"}
: ${FUZZ_OUTPUT:="$HOME/output"}
: ${FUZZ_BUILD:="$HOME/build"}
afl-fuzz -i $FUZZ_INPUT -o $FUZZ_OUTPUT -c $FUZZ_BUILD/cmplog/bin/fuzzing-persistent -m none -- $FUZZ_BUILD/asan/bin/fuzzing-persistent
