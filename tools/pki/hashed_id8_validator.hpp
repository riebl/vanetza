#pragma once

#include "CLI/Validators.hpp"
#include "hashed_id8.hpp"

namespace vanetza
{
namespace pki
{

class HashedId8Validator : public CLI::Validator
{
public:
    HashedId8Validator() : Validator("HashedId8")
    {
        func_ = [](const std::string& input) {
            if (valid_hashed_id8(input)) {
                return "";
            } else {
                return "HashedId8 must be given as 16 hex-digits";
            }
        };
    }
};

} // namespace pki
} // namespace vanetza
