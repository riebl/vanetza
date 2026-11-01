#include <vanetza/asn1/bit_string.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <cassert>
#include <cstdint>

namespace vanetza
{
namespace asn1
{

void allocate_bits(BIT_STRING_t& bits, std::size_t size)
{
    assert(bits.buf == nullptr);
    const std::size_t bytes = (size + 7) / 8;
    bits.buf = static_cast<uint8_t*>(allocate(bytes));
    bits.size = bytes;
    bits.bits_unused = static_cast<int>(bytes * 8 - size);
}

void set_bit(BIT_STRING_t& bits, std::size_t bit)
{
    bits.buf[bit / 8] |= static_cast<uint8_t>(0x80u >> (bit % 8));
}

} // namespace asn1
} // namespace vanetza
