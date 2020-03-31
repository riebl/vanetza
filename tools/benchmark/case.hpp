#ifndef BENCHMARK_CASE_HPP
#define BENCHMARK_CASE_HPP

#include <chrono>
#include <type_traits>
#include <string>
#include <vector>

class Case
{
public:
    virtual bool parse(const std::vector<std::string>&) = 0;
    virtual void prepare() = 0;
    virtual int execute() = 0;
    virtual ~Case() = default;
};

#endif /* BENCHMARK_CASE_HPP */
