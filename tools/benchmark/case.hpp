#ifndef BENCHMARK_CASE_HPP
#define BENCHMARK_CASE_HPP

#include <chrono>
#include <type_traits>

class Case
{
public:
    virtual void prepare() = 0;
    virtual int execute() = 0;
};

#endif /* BENCHMARK_CASE_HPP */
