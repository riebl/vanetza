#pragma once

#include "keys.hpp"
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace pki
{

boost::optional<PrivateKey> read_pem_private_key(const std::string&);

} // namespace pki
} // namespace vanetza
