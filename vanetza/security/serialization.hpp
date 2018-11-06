#ifndef SERIALIZATION_HPP_IENSIAL4
#define SERIALIZATION_HPP_IENSIAL4

#include <vanetza/common/serialization.hpp>
#include <vanetza/security/length_coding.hpp>
#include <cassert>
#include <list>

namespace vanetza
{
namespace security
{

using vanetza::serialize;
using vanetza::deserialize;

/**
 * \brief Serialize given length
 * \param ar to serialize in
 * \param size to encode
 */
void serialize_length(OutputArchive&, std::uintmax_t);

/**
 * \brief Deserialize length from a given archive
 * \param ar shall start with encoded length
 * \return length deserialized from archive
 */
std::uintmax_t deserialize_length(InputArchive&);

/**
 * \brief Calculate size of a list
 *
 * Sums up sizes of all list elements only, length itself is not included.
 * Therefore, the returned length is suitable as argument for serialize_length.
 *
 * \tparam T list element type
 * \param list
 * \return accumulated elements' size
 */
template<class T>
size_t get_size(const std::list<T>& list)
{
    size_t size = 0;
    for (auto& elem : list) {
        size += get_size(elem);
    }
    return size;
}

/**
 * \brief Trim (possibly) wider size type safely
 *
 *  This function throws an exception if size would be truncated.
 *
 * \param in wide size type
 * \return same size using narrow type
 */
std::size_t trim_size(std::uintmax_t in);

/** \brief Serialize from any given list into given binary archive
 * \tparam T the type of the list
 * \tparam ARGS all additional arguments for the underlying functions
 * \param ar to serialize in
 * \param list
 * \param args the additional arguments
 */
template<class T, typename... ARGS>
void serialize(OutputArchive& ar, const std::list<T>& list, ARGS&&... args)
{
    size_t size = get_size(list);
    serialize_length(ar, size);
    for (auto& elem : list) {
        serialize(ar, elem, std::forward<ARGS>(args)...);
    }
}

/** \brief Deserialize a list from given archive
 * \tparam T the type of the list
 * \tparam ARGS all additional arguments for the underlying functions
 * \param ar, shall start with the list
 * \param args the additional arguments
 * \return size of the deserialized list in bytes
 */
template<class T, typename... ARGS>
std::size_t deserialize(InputArchive& ar, std::list<T>& list, ARGS&&... args)
{
    const auto length = trim_size(deserialize_length(ar));
    std::intmax_t remainder = length;
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
