#ifndef CERTIFY_COMMAND_HPP
#define CERTIFY_COMMAND_HPP

#include <string>
#include <vector>

class Command
{
public:
    virtual int execute() = 0;
    virtual bool parse(const std::vector<std::string>&) = 0;
    virtual ~Command() = default;
};

#endif /* CERTIFY_COMMAND_HPP */
