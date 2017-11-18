#ifndef CERTIFY_COMMAND_HPP
#define CERTIFY_COMMAND_HPP

#include <boost/program_options.hpp>

class Command
{
public:
    virtual int execute() = 0;
    virtual void parse(std::vector<std::string>&) = 0;
};

#endif /* CERTIFY_COMMAND_HPP */
