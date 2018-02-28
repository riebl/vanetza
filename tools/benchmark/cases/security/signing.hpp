#ifndef BENCHMARK_CASES_SECURITY_SIGNING_HPP
#define BENCHMARK_CASES_SECURITY_SIGNING_HPP

#include "base.hpp"

class SecuritySigningCase : public SecurityBaseCase
{
public:
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    unsigned messages;
    std::string signer_info_type;
};

#endif /* BENCHMARK_CASES_SECURITY_SIGNING_HPP */
