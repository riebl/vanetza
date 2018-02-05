#ifndef CERTIFY_COMMANDS_SHOW_CERTIFICATE_HPP
#define CERTIFY_COMMANDS_SHOW_CERTIFICATE_HPP

#include "command.hpp"

class ShowCertificateCommand : public Command
{
public:
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string certificate_path;
};

#endif /* CERTIFY_COMMANDS_SHOW_CERTIFICATE_HPP */
