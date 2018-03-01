#ifndef BENCHMARK_OPTIONS_HPP
#define BENCHMARK_OPTIONS_HPP

#include "case.hpp"
#include <memory>

std::unique_ptr<Case> parse_options(int argc, const char* argv[]);

#endif /* BENCHMARK_OPTIONS_HPP */
