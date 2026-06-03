#include "hashed_id8.hpp"
#include "hexstring.hpp"
#include <vanetza/asn1/security/HashedId8.h>
#include <boost/algorithm/hex.hpp>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace vanetza
{
namespace pki
{

HashedId8::HashedId8(const Sha256Hash& hash)
{
    std::copy(hash.octets.end() - 8, hash.octets.end(), octets.data());
}

HashedId8::HashedId8(const Sha384Hash& hash)
{
    std::copy(hash.octets.end() - 8, hash.octets.end(), octets.data());
}

boost::optional<HashedId8> HashedId8::from_hexstring(const std::string& hex)
{
    if (hex.size() == 16) {
        try {
            HashedId8 result;
            boost::algorithm::unhex(hex, result.octets.data());
            return result;
        } catch (boost::algorithm::hex_decode_error&) {
        }
    }

    return boost::none;
}

boost::optional<HashedId8> HashedId8::from_buffer(const OCTET_STRING_t& os)
{
    HashedId8 result;
    if (os.buf != nullptr && os.size == result.octets.size()) {
        std::copy_n(os.buf, result.octets.size(), result.octets.data());
        return result;
    }

    return boost::none;
}

std::string hexstring(const HashedId8& id)
{
    return hexstring(id.octets.data(), id.octets.size());
}

bool valid_hashed_id8(const std::string& hex)
{
    auto all_hex = [](const std::string& input) {
        return std::all_of(input.begin(), input.end(), [](unsigned char c) { return std::isxdigit(c); });
    };

    return (hex.size() == 16 && all_hex(hex));
}

bool operator==(const HashedId8& a, const HashedId8& b)
{
    return a.octets == b.octets;
}

bool operator!=(const HashedId8& a, const HashedId8& b)
{
    return a.octets != b.octets;
}

bool operator<(const HashedId8& a, const HashedId8& b)
{
    return a.octets < b.octets;
}

bool lexical_cast(const std::string& input, HashedId8& hid8)
{
    auto staging = HashedId8::from_hexstring(input);
    if (staging) {
        hid8 = *staging;
    }
    return staging.has_value();
}

bool equals(const Vanetza_Security_HashedId8_t& asn, const HashedId8& own)
{
    return asn.size == own.octets.size() && std::memcmp(asn.buf, own.octets.data(), own.octets.size()) == 0;
}

} // namespace pki
} // namespace vanetza
