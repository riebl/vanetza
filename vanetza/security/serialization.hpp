#ifndef SERIALIZATION_HPP_IENSIAL4
#define SERIALIZATION_HPP_IENSIAL4

#include <vanetza/geonet/serialization.hpp>
#include <vanetza/security/length_coding.hpp>
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

template<class T>
void serialize(OutputArchive& ar, std::list<T> list) {
    size_t size = get_size(list);
    serialize_length(ar, size);
    for (auto& elem : list) {
        serialize(ar, elem);
    }
}

template<class T>
size_t deserialize(InputArchive& ar, std::list<T>& list)
{
    size_t size = deserialize_length(ar);
    size_t ret_size = size;
    while (size > 0) {
        T elem;
        size -= deserialize(ar, elem);
        list.push_back(T(elem));
    }
    return ret_size;
}

} // namespace security
} // namespace vanetza

#endif /* SERIALIZATION_HPP_IENSIAL4 */
