#ifndef CERTIFY_COMMANDS_MIGRATE_KEY_HPP
#define CERTIFY_COMMANDS_MIGRATE_KEY_HPP

#include "command.hpp"

/**
 * Import a private key file of former versions into a security module and save its key reference
 */
class MigrateKeyCommand : public Command
{
public:
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string input;
    std::string output;
    std::string security_module;
};

#endif /* CERTIFY_COMMANDS_MIGRATE_KEY_HPP */
