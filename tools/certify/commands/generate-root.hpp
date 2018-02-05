#ifndef CERTIFY_COMMANDS_GENERATE_ROOT_HPP
#define CERTIFY_COMMANDS_GENERATE_ROOT_HPP

#include "command.hpp"

class GenerateRootCommand : public Command
{
public:
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string cert_key;
    std::string output;
    std::string subject_name;
    int validity_days;
};

#endif /* CERTIFY_COMMANDS_GENERATE_ROOT_HPP */
