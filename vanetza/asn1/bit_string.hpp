#ifndef BIT_STRING_HPP_P4X8NW6T
#define BIT_STRING_HPP_P4X8NW6T

#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/support/BIT_STRING.h>
#include <cstddef>
#include <cstdint>

namespace vanetza
{
namespace asn1
{

/**
 * Allocate a zeroed bit string buffer
 *
 * \pre bits has no buffer yet
 * \param bits bit string (destination)
 * \param size number of bits
 * \throw asn1::asn1c_exception if memory allocation fails
 */
inline void allocate_bits(BIT_STRING_t& bits, std::size_t size)
{
    const std::size_t bytes = (size + 7) / 8;
    bits.buf = static_cast<uint8_t*>(allocate(bytes));
    bits.size = bytes;
    bits.bits_unused = static_cast<int>(bytes * 8 - size);
}

/**
 * Set a bit of a bit string, numbered from the most significant bit of the first byte
 * as done for named bits in ASN.1
 *
 * \pre bit < number of bits
 * \param bits bit string (destination)
 * \param bit index of the bit to set, counted from zero
 */
inline void set_bit(BIT_STRING_t& bits, std::size_t bit)
{
    bits.buf[bit / 8] |= static_cast<uint8_t>(0x80u >> (bit % 8));
}

} // namespace asn1
} // namespace vanetza

#endif /* BIT_STRING_HPP_P4X8NW6T */
