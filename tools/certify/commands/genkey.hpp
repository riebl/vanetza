#ifndef CERTIFY_COMMANDS_GENKEY_HPP
#define CERTIFY_COMMANDS_GENKEY_HPP

#include "../command.hpp"
#include <string>

class GenkeyCommand : public Command {
public:
    std::string output;

    void parse(std::vector<std::string>&) override;
    int execute() override;
};

#endif /* CERTIFY_COMMANDS_GENKEY_HPP */
