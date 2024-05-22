#ifndef SERIALIZATION_HPP_IENSIAL4
#define SERIALIZATION_HPP_IENSIAL4

#include <vanetza/common/serialization.hpp>
#include <vanetza/security/v2/length_coding.hpp>
#include <cassert>
#include <list>

namespace vanetza
{
namespace security
{
namespace v2
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
    using vanetza::security::v2::get_size;
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
    using vanetza::security::v2::get_size;
    using vanetza::security::v2::serialize;
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
    using vanetza::security::v2::deserialize;
    static const std::size_t length_limit = 4096;

    const auto length = trim_size(deserialize_length(ar));
    if (length <= length_limit) {
        std::intmax_t remainder = length;
        while (remainder > 0) {
            T t;
            std::size_t size = deserialize(ar, t, std::forward<ARGS>(args)...);
            if (size <= remainder && ar.is_good()) {
                list.push_back(std::move(t));
                remainder -= size;
            } else {
                ar.fail(InputArchive::ErrorCode::ConstraintViolation);
                break;
            }
        }
    } else {
        ar.fail(InputArchive::ErrorCode::ExcessiveLength);
    }

    return length;
}

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* SERIALIZATION_HPP_IENSIAL4 */
