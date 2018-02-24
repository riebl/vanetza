#ifndef UPPERTESTER_SERIALIZATION_HPP
#define UPPERTESTER_SERIALIZATION_HPP

#include <vanetza/common/serialization.hpp>

using vanetza::InputArchive;
using vanetza::OutputArchive;

template<typename T>
void serialize(OutputArchive& oa, T&& t)
{
    using vanetza::serialize;
    serialize(oa, std::forward<T>(t));
}

#endif /* UPPERTESTER_SERIALIZATION_HPP */
