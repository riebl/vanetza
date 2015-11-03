#ifndef SERIALIZATION_HPP_ZWGI3RCG
#define SERIALIZATION_HPP_ZWGI3RCG

#include <vanetza/security/serialization.hpp>
#include <vanetza/security/tests/web_validator.hpp>
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

template<typename T, typename... ARGS>
T deserialize(const char* input, ARGS&&... args)
{
    std::stringstream stream;
    stream_from_string(stream, input);

    T t;
    InputArchive ar(stream);
    deserialize(ar, t, std::forward<ARGS>(args)...);

    return t;
}

} // namespace security
} // namespace vanetza

#endif /* SERIALIZATION_HPP_ZWGI3RCG */

