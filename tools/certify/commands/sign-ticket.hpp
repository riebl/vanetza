#ifndef CERTIFY_COMMANDS_SIGN_TICKET_HPP
#define CERTIFY_COMMANDS_SIGN_TICKET_HPP

#include "../command.hpp"
#include <string>

class SignTicketCommand : public Command {
public:
    std::string output;
    std::string sign_key;
    std::string sign_cert;
    std::string subject_key;
    int validity_days;

    void parse(std::vector<std::string>&) override;
    int execute() override;
};

#endif /* CERTIFY_COMMANDS_SIGN_TICKET_HPP */
