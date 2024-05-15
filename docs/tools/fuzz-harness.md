# fuzz-harness

The fuzz harness for vanetza is a testing tool designed to identify bugs, vulnerabilities, and unexpected behaviors within the vanetza codebase. Fuzz testing, also known as fuzzing, involves providing invalid, unexpected, or random data as input to a program to uncover errors or security issues.
## Requirements

- AFL++: You will need AFL++ installed on your system. Refer to the AFL++ documentation for installation instructions: https://aflplus.plus/docs/install/

## Usage

### Compile the instrumentation CmpLog

```
mkdir build_cmplog && cd build_cmplog/
```

```
export AFL_LLVM_CMPLOG=1
```

```
cmake .. \
   -DBUILD_FUZZ=ON \
   -DCMAKE_C_COMPILER=afl-clang-lto \
   -DCMAKE_CXX_COMPILER=afl-clang-lto++
```

```
make
```

Make sure to `unset AFL_LLVM_CMPLOG` afterwards.

### Compile with Address Sanitizer

Same as before but this time with:

```
mkdir build_asan && cd build_asan/
```

```
export AFL_USE_ASAN=1
```

### Fuzz

```
mkdir output
```

```
afl-fuzz -i input/ -o output/ -c ../../build_cmplog/bin/routerIndicatePersistentFuzz -m none -- ../../build_asan/bin/routerIndicatePersistentFuzz
```

If it crashes immediately, try again a few times. 

### Analyse
You can use `routerIndicateTest` to investigate the crash and get more information about the possible problems. The address sanitizer is enabled by default. If you're not interested in memory leaks, make sure to disable the leak sanatizer with the environment variable `ASAN_OPTIONS=detect_leaks=0`.
