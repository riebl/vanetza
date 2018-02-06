#ifndef CERTIFY_COMMANDS_EXTRACT_PUBLIC_KEY_HPP
#define CERTIFY_COMMANDS_EXTRACT_PUBLIC_KEY_HPP

#include "command.hpp"

class ExtractPublicKeyCommand : public Command
{
public:
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string output;
    std::string certificate_path;
    std::string private_key_path;
};

#endif /* CERTIFY_COMMANDS_EXTRACT_PUBLIC_KEY_HPP */
