#ifndef LENGTH_CODING_HPP_UQ1OIDUN
#define LENGTH_CODING_HPP_UQ1OIDUN

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/geonet/serialization.hpp>
#include <boost/optional.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

namespace vanetza
{
namespace security
{
typedef boost::archive::binary_iarchive InputArchive;
typedef boost::archive::binary_oarchive OutputArchive;

/**
 * Calculate length coding for variable length fields
 * \param length Data field length in bytes, e.g. size of a buffer
 * \return byte buffer containing encoded length, prepend to data
 */
ByteBuffer encode_length(std::size_t length);

/**
 * Extract data field of variable length from byte buffer
 * \param buffer Buffer with input data
 * \return range comprising data only if successful or whole buffer if error occurred
 */
boost::iterator_range<ByteBuffer::const_iterator> decode_length_range(const ByteBuffer& buffer);

/**
 * Extract length information
 * \param buffer Buffer with input data, shall start with first byte of encoded length
 * \return tuple of iterator pointing at start of payload buffer and its length
 */
boost::optional<std::tuple<ByteBuffer::const_iterator, std::size_t>> decode_length(
    const ByteBuffer& buffer);

/**
 * Count number of leading one bits
 * \param a byte
 * \return number of leadings ones in given byte
 */
std::size_t count_leading_ones(uint8_t);

/**
 * Serialize given length
 * \param size to encode
 * \param archive to serialize in
 */
void serialize_length(OutputArchive&, size_t);

/**
 * calculates bytes, needed to store a given size
 * \param size
 * \return number of bytes needed to store length
 */
std::size_t length_coding_size(size_t);

/**
 * Deserialize length from a given archive
 * \param archive, shall start with length encoding
 * \return length
 */
size_t deserialize_length(InputArchive&);

} // namespace security
} // namespace vanetza

#endif /* LENGTH_CODING_HPP_UQ1OIDUN */

