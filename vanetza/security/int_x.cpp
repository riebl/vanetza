#include <vanetza/security/int_x.hpp>

namespace vanetza
{
namespace security
{

void IntX::set(integer_type x)
{
    m_octets.clear();
    for (std::size_t i = 0; i < sizeof(integer_type); ++i) {
        static const auto msb_shift = (sizeof(integer_type) - 1) * 8;
        static const auto msb_mask = static_cast<integer_type>(0xff) << msb_shift;
        if (!m_octets.empty() || (x & msb_mask) != 0) {
            m_octets.push_back(x >> msb_shift);
        }
        x <<= 8;
    }
}

IntX::integer_type IntX::get() const
{
    integer_type result = 0;
    for (uint8_t octet : m_octets) {
        result <<= 8;
        result |= octet;
    }
    return result;
}

bool IntX::operator==(const IntX& other) const
{
    return this->m_octets == other.m_octets;
}

ByteBuffer IntX::encode() const
{
    ByteBuffer result;
    if (sizeof(std::size_t) >= m_octets.size()) {
        std::size_t length = this->get<std::size_t>();
        result = encode_length(length);
    }
    return result;
}

boost::optional<IntX> IntX::decode(const ByteBuffer& buffer)
{
    boost::optional<IntX> result;
    auto decoded_tuple = decode_length(buffer);
    if (decoded_tuple) {
        IntX tmp;
        tmp.set(std::get<1>(*decoded_tuple));
        result = tmp;
    }
    return result;
}

size_t get_size(IntX intx)
{
    return (length_coding_size(intx.size()) + intx.size());
}

void serialize(OutputArchive& ar, const IntX& intx)
{
    ByteBuffer buf = intx.encode();
    for (auto byte : buf) {
        ar << byte;
    }
}

void deserialize(InputArchive& ar, IntX& intx)
{
    size_t size = deserialize_length(ar);
    intx.set(int(size));
}

} // namespace security
} // namespace vanetza
