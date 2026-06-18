#pragma once

#include "CLI/Validators.hpp"
#include "hexstring.hpp"

namespace vanetza
{
namespace pki
{

class HexStringValidator : public CLI::Validator
{
public:
    HexStringValidator() : Validator("HEX")
    {
        func_ = [](const std::string& input) {
            if (is_valid_hexstring(input)) {
                return "";
            } else {
                return "value must be an even, non-zero number of hex digits";
            }
        };
    }
};

} // namespace pki
} // namespace vanetza
