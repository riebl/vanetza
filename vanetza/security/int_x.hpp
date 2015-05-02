#ifndef INT_X_HPP_RW3TJBBI
#define INT_X_HPP_RW3TJBBI

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/length_coding.hpp>
#include <vanetza/security/serialization.hpp>
#include <list>

namespace vanetza {
namespace security {

class IntX {
public:
    using integer_type = std::uintmax_t;
    using octets_type = std::list<uint8_t>;

    void set(integer_type x);
    integer_type get() const;

    template<typename T>
    T get() const {
        assert(sizeof(T) >= size());
        return get();
    }

    std::size_t size() const {
        return m_octets.size();
    }

    ByteBuffer encode() const;
    static boost::optional<IntX> decode(const ByteBuffer&);

private:
    octets_type m_octets;
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

