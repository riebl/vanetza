#ifndef SERIALIZATION_HPP_ZFDJQSWI
#define SERIALIZATION_HPP_ZFDJQSWI

#include <vanetza/common/archives.hpp>
#include <vanetza/common/serialization.hpp>
#include <sstream>

namespace vanetza
{
namespace geonet
{

/**
 * \brief Serialize and deserialize an object
 *
 * Source object is serialized and deserialized
 * object form this binary representation is returned.
 *
 * \tparam T the type of the result
 * \param source serialize from this object
 * \return deserialized object (should be equal to source)
 */
template<typename T>
T serialize_roundtrip(const T& source)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(source, oa);

    T result;
    InputArchive ia(stream);
    deserialize(result, ia);

    return result;
}

template<typename T>
std::size_t serialize_length(const T& source)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(source, oa);
    return stream.tellp();
}

} // namespace geonet
} // namespace vanetza

#endif /* SERIALIZATION_HPP_ZFDJQSWI */
