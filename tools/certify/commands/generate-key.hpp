#ifndef CERTIFY_COMMANDS_GENERATE_KEY_HPP
#define CERTIFY_COMMANDS_GENERATE_KEY_HPP

#include "command.hpp"

class GenerateKeyCommand : public Command
{
public:
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string output;
};

#endif /* CERTIFY_COMMANDS_GENERATE_KEY_HPP */
