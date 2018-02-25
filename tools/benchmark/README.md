# Benchmark

*Benchmark* is a tool to run various benchmarks for Vanetza code.

## Installation

You need to enable building of this component separately.
Run `cmake -D BUILD_BENCHMARK=ON ..` in your build directory (assuming you followed the instructions in the main `README.md`).
You should be able to find `bin/benchmark` in your build directory afterwards.

## Running

You can run `bin/benchmark --help` to get a list of available benchmarks.
You can run these with `bin/benchmark <name>` then.

## Acknowledgement

This application has been initially developed [Niklas Keller](https://github.com/kelunik).
