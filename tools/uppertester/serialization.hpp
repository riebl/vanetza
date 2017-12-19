#ifndef UPPERTESTER_SERIALIZATION
#define UPPERTESTER_SERIALIZATION

#include <vanetza/common/serialization.hpp>

using vanetza::InputArchive;
using vanetza::OutputArchive;

template<typename T>
void serialize(OutputArchive& oa, T&& t)
{
    using vanetza::serialize;
    serialize(oa, std::forward<T>(t));
}

#endif /* UPPERTESTER_SERIALIZATION */
