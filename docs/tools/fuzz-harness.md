# fuzz-harness

The fuzz harness for Vanetza is a testing tool designed to identify bugs, vulnerabilities, and unexpected behaviors within Vanetza's codebase. Fuzz testing, also known as fuzzing, involves providing invalid, unexpected, or random data as input to a program to uncover errors or security issues.

## Requirements

You will need AFL++ installed on your system.
Please refer to the [AFL++ documentation](https://aflplus.plus/docs/install/) for installation instructions.
Alternatively, you can use the scripts located at *tools/fuzz-harness* for running fuzz tests in a Docker container.

## Usage

Running the script *fuzz-harness/docker.sh* will build a suitable Docker container based on the official *aflplusplus/aflplusplus* image.
As soon as the container is ready, the script launches the built container and maps your local user and some Vanetza directories into it.

Within the container, you can compile the *fuzz-harness* using the AFL++ toolchain by invoking the *compile.sh* script.
The *fuzz.sh* script is a convenient way to run the built harness with *afl-fuzz*.
If it crashes immediately, try again a few times. 

### Analyse

Fuzzing is executing the *fuzzing-persistent* executable.
You can use its sibling *fuzzing-run* to investigate a particular crash and get more information about the possible problems.
The address sanitizer is enabled by default. If you're not interested in memory leaks, make sure to disable the leak sanatizer by setting the environment variable `ASAN_OPTIONS=detect_leaks=0`.

You may also want to classify the found issues using *casr-afl*: `casr-afl -i output -o output/casr`
The classification process also eliminates duplicate issues.
