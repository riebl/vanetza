#ifndef CERTIFY_COMMANDS_ROOT_CA_HPP
#define CERTIFY_COMMANDS_ROOT_CA_HPP

#include "../command.hpp"
#include <string>

class RootCaCommand : public Command {
public:
    std::string cert_key;
    std::string output;
    std::string subject_name;
    int validity_days;

    void parse(std::vector<std::string>&) override;
    int execute() override;
};

#endif /* CERTIFY_COMMANDS_ROOT_CA_HPP */
