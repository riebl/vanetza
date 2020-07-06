# Benchmark

*Benchmark* is a tool to benchmark some components of Vanetza.
At the moment, benchmarks for signing and validating packets exist.

## Installation

Benchmarks are not built by default, so you need to enable them explicitly.
Run `cmake -D BUILD_BENCHMARK=ON ..` in your build directory to do so and start the build process again.
You should be able to find `bin/benchmark` in your build directory afterwards.

## Running

You can run `bin/benchmark --help` to get a list of available benchmarks.
You can run these with `bin/benchmark <name>` then.

## Acknowledgement

This application has been initially developed [Niklas Keller](https://github.com/kelunik).
