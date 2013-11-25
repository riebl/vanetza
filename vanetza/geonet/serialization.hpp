#ifndef SERIALIZATION_HPP_U2YGHSPB
#define SERIALIZATION_HPP_U2YGHSPB

#include <vanetza/common/byte_order.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/units/quantity.hpp>
#include <type_traits>

namespace vanetza
{
namespace geonet
{

typedef boost::archive::binary_iarchive InputArchive;
typedef boost::archive::binary_oarchive OutputArchive;

template<typename T, ByteOrder ORDER>
void serialize(EndianType<T, ORDER> value, OutputArchive& ar)
{
    typedef typename decltype(value)::network_type network_type;
    T tmp = static_cast<network_type>(value).get();
    ar << tmp;
}

template<typename T, ByteOrder ORDER>
void deserialize(EndianType<T, ORDER>& value, InputArchive& ar)
{
    T tmp;
    ar >> tmp;
    value = network_cast<T>(tmp);
}

template<typename T>
void deserialize(T& value, InputArchive& ar)
{
    T tmp;
    ar >> tmp;
    value = ntoh(tmp);
}

template<typename U, typename T>
void serialize(boost::units::quantity<U, T> q, OutputArchive& ar)
{
    static_assert(std::is_integral<T>::value,
            "Only integral based quantities are supported");
    auto tmp = hton(q.value());
    ar << tmp;
}

template<typename U, typename T>
void deserialize(boost::units::quantity<U, T>& q, InputArchive& ar)
{
    static_assert(std::is_integral<T>::value,
            "Only integral based quantities are supported");
    T tmp;
    ar >> tmp;
    q = boost::units::quantity<U, T>::from_value(ntoh(tmp));
}

} // namespace geonet
} // namespace vanetza

#endif /* SERIALIZATION_HPP_U2YGHSPB */

