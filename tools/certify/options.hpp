#ifndef CERTIFY_OPTIONS_HPP
#define CERTIFY_OPTIONS_HPP

#include "command.hpp"
#include <boost/variant/variant.hpp>
#include <boost/variant/get.hpp>

std::unique_ptr<Command> parse_options(int argc, const char *argv[]);

#endif /* CERTIFY_OPTIONS_HPP */
