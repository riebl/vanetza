#include "hexstring.hpp"
#include <boost/algorithm/hex.hpp>
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

} // namespace pki
} // namespace vanetza
