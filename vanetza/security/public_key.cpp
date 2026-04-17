#include <vanetza/security/public_key.hpp>
#include <boost/algorithm/hex.hpp>
#include <iterator>

namespace vanetza
{
namespace security
{

std::string canonical_hexstring(const PublicKey& key)
{
    const std::size_t expected_length = key_length(key.type);
    if (expected_length == 0 || key.x.size() != expected_length) {
        return {};
    }

    std::string input;
    switch (key.compression) {
        case KeyCompression::NoCompression:
            if (key.y.size() != expected_length) {
                return {};
            }
            input.push_back(*key.y.rbegin() % 2 == 0 ? 0x02 : 0x03);
            break;
        case KeyCompression::Y0:
            input.push_back(0x02);
            break;
        case KeyCompression::Y1:
            input.push_back(0x03);
            break;
        default:
            return {};
    }
    std::copy(key.x.begin(), key.x.end(), std::back_inserter(input));
    return boost::algorithm::hex(input);
}

} // namespace security
} // namespace vanetza
