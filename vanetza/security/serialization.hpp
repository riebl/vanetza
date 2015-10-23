#ifndef SERIALIZATION_HPP_IENSIAL4
#define SERIALIZATION_HPP_IENSIAL4

#include <vanetza/geonet/serialization.hpp>
#include <vanetza/security/length_coding.hpp>
#include <cassert>
#include <list>
#include <type_traits>

namespace vanetza
{
namespace security
{

using vanetza::geonet::InputArchive;
using vanetza::geonet::OutputArchive;

/**
 * Serialize given length
 * \param size to encode
 * \param archive to serialize in
 */
void serialize_length(OutputArchive&, size_t);

/**
 * Deserialize length from a given archive
 * \param archive, shall start with length encoding
 * \return length
 */
size_t deserialize_length(InputArchive&);

template<class T>
typename std::enable_if<std::is_enum<T>::value>::type serialize(OutputArchive& ar, const T& t)
{
    geonet::serialize(host_cast(static_cast<typename std::underlying_type<T>::type const>(t)), ar);
}

template<class T>
typename std::enable_if<std::is_enum<T>::value>::type deserialize(InputArchive& ar, T& t)
{
    typename std::underlying_type<T>::type tmp;
    geonet::deserialize(tmp, ar);
    t = static_cast<T>(tmp);
}

template<class T>
size_t get_size(std::list<T> list)
{
    size_t size = 0;
    for (auto elem : list) {
        size += get_size(elem);
    }
    return size;
}

template<class T, typename... ARGS>
void serialize(OutputArchive& ar, const std::list<T>& list, ARGS&&... args)
{
    size_t size = get_size(list);
    serialize_length(ar, size);
    for (auto& elem : list) {
        serialize(ar, elem, std::forward<ARGS>(args)...);
    }
}

template<class T, typename... ARGS>
size_t deserialize(InputArchive& ar, std::list<T>& list, ARGS&&... args)
{
    const size_t length = deserialize_length(ar);
    int remainder = length;
    while (remainder > 0) {
        T t;
        remainder -= deserialize(ar, t, std::forward<ARGS>(args)...);
        list.push_back(std::move(t));
    }
    assert(remainder == 0);
    return length;
}

} // namespace security
} // namespace vanetza

#endif /* SERIALIZATION_HPP_IENSIAL4 */
