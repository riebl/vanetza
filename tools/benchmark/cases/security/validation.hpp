#ifndef BENCHMARK_CASES_SECURITY_VALIDATION_HPP
#define BENCHMARK_CASES_SECURITY_VALIDATION_HPP

#include "base.hpp"

class SecurityValidationCase : public SecurityBaseCase
{
public:
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    unsigned identities;
    unsigned messages;
    std::string signer_info_type;
};

#endif /* BENCHMARK_CASES_SECURITY_VALIDATION_HPP */
