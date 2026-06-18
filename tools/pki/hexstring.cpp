#include "hexstring.hpp"
#include <boost/algorithm/hex.hpp>
#include <algorithm>
#include <cctype>
#include <iterator>

namespace vanetza
{
namespace pki
{

std::string hexstring(const std::uint8_t* buf, std::size_t len)
{
    std::string out;
    boost::algorithm::hex(buf, buf + len, std::back_inserter(out));
    return out;
}

std::string hexstring(const std::string& input)
{
    static_assert(sizeof(std::string::value_type) == sizeof(std::uint8_t));
    return hexstring(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
}

std::string hexstring(const ByteBuffer& buffer)
{
    return hexstring(buffer.data(), buffer.size());
}

bool is_valid_hexstring(const std::string& input)
{
    return !input.empty() && input.size() % 2 == 0 &&
        std::all_of(input.begin(), input.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

std::string parse_hexstring(const std::string& input)
{
    std::string out;
    boost::algorithm::unhex(input, std::back_inserter(out));
    return out;
}

} // namespace pki
} // namespace vanetza
