#ifndef INT_X_HPP_RW3TJBBI
#define INT_X_HPP_RW3TJBBI

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/serialization.hpp>
#include <boost/operators.hpp>
#include <boost/optional.hpp>
#include <cstdint>
#include <list>

namespace vanetza
{
namespace security
{

class IntX : public boost::equality_comparable<IntX>
{
public:
    using integer_type = std::uintmax_t;
    IntX();

    void set(integer_type x);
    integer_type get() const;

    bool operator==(const IntX&) const;

    ByteBuffer encode() const;
    static boost::optional<IntX> decode(const ByteBuffer&);

private:
    integer_type m_value;
};

/**
 * Serializes an IntX into a binary archive
 * \param achive to serialize in, IntX to serialize
 */
void serialize(OutputArchive&, const IntX&);

/**
 * Deserializes an IntX from a binary archive
 * \param archive with a serialized IntX at the beginning, IntX to deserialize
 * \return size of the deserialized IntX
 */
void deserialize(InputArchive&, IntX&);

/**
 * Calculates size of an IntX
 * \param IntX
 * \return size_t containing the number of octets needed to serialize the IntX
 */
size_t get_size(IntX);

} // namespace security
} // namespace vanetza

#endif /* INT_X_HPP_RW3TJBBI */

