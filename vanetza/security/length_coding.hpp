#ifndef LENGTH_CODING_HPP_UQ1OIDUN
#define LENGTH_CODING_HPP_UQ1OIDUN

#include <vanetza/common/byte_buffer.hpp>
#include <boost/range/iterator_range.hpp>
#include <cstdint>
#include <tuple>

namespace vanetza
{
namespace security
{

/**
 * Calculate length coding for variable length fields
 * \param length Data field length in bytes, e.g. size of a buffer
 * \return byte buffer containing encoded length, prepend to data
 */
ByteBuffer encode_length(std::uintmax_t length);

/**
 * Extract length information
 * \param buffer Buffer with input data, shall start with first byte of encoded length
 * \return iterator pointing at start of payload buffer (begin indicates error) and its length
 */
std::tuple<ByteBuffer::const_iterator, std::uintmax_t> decode_length(const ByteBuffer& buffer);

/**
 * Count number of leading one bits
 * \param a byte
 * \return number of leadings ones in given byte
 */
std::size_t count_leading_ones(std::uint8_t);

/**
 * Determines the number of bytes, needed to store a given size
 * \param size
 * \return number of bytes needed to store length
 */
std::size_t length_coding_size(std::uintmax_t);

} // namespace security
} // namespace vanetza

#endif /* LENGTH_CODING_HPP_UQ1OIDUN */

