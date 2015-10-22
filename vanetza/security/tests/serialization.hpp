#ifndef SERIALIZATION_HPP_ZWGI3RCG
#define SERIALIZATION_HPP_ZWGI3RCG

#include <vanetza/security/serialization.hpp>
#include <sstream>

namespace vanetza
{
namespace security
{

template<typename T>
T serialize_roundtrip(const T& source)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, source);

    T result;
    InputArchive ia(stream);
    deserialize(ia, result);

    return result;
}

} // namespace security
} // namespace vanetza

#endif /* SERIALIZATION_HPP_ZWGI3RCG */

