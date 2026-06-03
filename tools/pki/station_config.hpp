#pragma once

#include "hashed_id8.hpp"
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace pki
{

class StationConfiguration
{
public:
    virtual ~StationConfiguration() = default;

    virtual std::string get_canonical_identifier() const = 0;
    virtual void set_canonical_identifier(const std::string&) = 0;

    virtual boost::optional<HashedId8> get_ec_identifier() const = 0;
    virtual void set_ec_identifier(const HashedId8&) = 0;

    virtual boost::optional<HashedId8> get_root_ca() const = 0;
    virtual void set_root_ca(const HashedId8&) = 0;
};

} // namespace pki
} // namespace vanetza
