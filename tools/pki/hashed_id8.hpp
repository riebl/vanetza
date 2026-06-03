#pragma once

#include "sha.hpp"
#include <boost/optional/optional.hpp>
#include <array>
#include <cstdint>
#include <string>

// forward declarations
typedef struct OCTET_STRING OCTET_STRING_t;
typedef OCTET_STRING_t Vanetza_Security_HashedId8_t;

namespace vanetza
{
namespace pki
{

struct HashedId8
{
    HashedId8() = default;
    explicit HashedId8(const Sha256Hash&);
    explicit HashedId8(const Sha384Hash&);
    static boost::optional<HashedId8> from_hexstring(const std::string&);
    static boost::optional<HashedId8> from_buffer(const OCTET_STRING_t&);

    std::array<std::uint8_t, 8> octets;
};

bool operator==(const HashedId8&, const HashedId8&);
bool operator!=(const HashedId8&, const HashedId8&);
bool operator<(const HashedId8&, const HashedId8&);

std::string hexstring(const HashedId8&);
bool valid_hashed_id8(const std::string& hex);

bool lexical_cast(const std::string&, HashedId8&);

bool equals(const Vanetza_Security_HashedId8_t&, const HashedId8&);

} // namespace pki
} // namespace vanetza
