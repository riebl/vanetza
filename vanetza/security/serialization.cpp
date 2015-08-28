#include <vanetza/security/length_coding.hpp>
#include <vanetza/security/serialization.hpp>

namespace vanetza
{
namespace security
{

void serialize_length(OutputArchive& ar, size_t length)
{
    ByteBuffer buf;
    buf = encode_length(length);
    for (auto it = buf.begin(); it != buf.end(); it++) {
        geonet::serialize(uint8be_t(*it), ar);
    }
}

size_t deserialize_length(InputArchive& ar)
{
    ByteBuffer buf;
    uint8_t elem;
    geonet::deserialize(elem, ar);
    buf.push_back(elem);
    size_t leading = count_leading_ones(elem);
    for (size_t c = 0; c < leading; ++c) {
        geonet::deserialize(elem, ar);
        buf.push_back(elem);
    }
    auto tup = decode_length(buf);
    return std::get<1>(*tup);
}

} // namespace security
} // namespace vanetza
