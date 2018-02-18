#ifndef CERTIFY_COMMANDS_GENERATE_AA_HPP
#define CERTIFY_COMMANDS_GENERATE_AA_HPP

#include "command.hpp"

class GenerateAaCommand : public Command
{
public:
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string output;
    std::string sign_key_path;
    std::string sign_cert_path;
    std::string subject_key_path;
    std::string subject_name;
    int validity_days;
    std::vector<unsigned> aids;
};

#endif /* CERTIFY_COMMANDS_GENERATE_AA_HPP */
