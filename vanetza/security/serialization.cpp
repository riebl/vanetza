#include <vanetza/security/length_coding.hpp>
#include <vanetza/security/serialization.hpp>
#include <cassert>
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace vanetza
{
namespace security
{

template<typename T>
std::size_t trim_size_impl(T in, typename std::enable_if<std::is_same<T, std::size_t>::value>::type* = nullptr)
{
    return in;
}

template<typename T>
std::size_t trim_size_impl(T in, typename std::enable_if<!std::is_same<T, std::size_t>::value>::type* = nullptr)
{
    if (in > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error("given size exceeds limits of std::size_t");
    }
    return static_cast<std::size_t>(in);
}

std::size_t trim_size(std::uintmax_t in)
{
    return trim_size_impl(in);
}


void serialize_length(OutputArchive& ar, std::uintmax_t length)
{
    ByteBuffer buf;
    buf = encode_length(length);
    for (auto it = buf.begin(); it != buf.end(); it++) {
        ar << *it;
    }
}

std::uintmax_t deserialize_length(InputArchive& ar)
{
    ByteBuffer buf(1);
    ar >> buf[0];
    const size_t leading = count_leading_ones(buf[0]);
    buf.resize(leading + 1);
    for (size_t c = 1; c <= leading; ++c) {
        ar >> buf[c];
    }
    auto tup = decode_length(buf);
    assert(std::get<0>(tup) != buf.begin());
    return std::get<1>(tup);
}

} // namespace security
} // namespace vanetza
