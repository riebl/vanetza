#ifndef BYTE_ORDER_HPP_LPUJ094I
#define BYTE_ORDER_HPP_LPUJ094I

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <type_traits>
#include <endian.h>

namespace vanetza
{
namespace detail
{

template<class T, int SIZE = sizeof(T)>
struct byte_order_converter;

template<class T>
struct byte_order_converter<T, 1>
{
    static T host_to_network(T value) { return value; }
    static T network_to_host(T value) { return value; }
};

template<class T>
struct byte_order_converter<T, 2>
{
    static T host_to_network(T value) { return htobe16(value); }
    static T network_to_host(T value) { return be16toh(value); }
};

template<class T>
struct byte_order_converter<T, 4>
{
    static T host_to_network(T value) { return htobe32(value); }
    static T network_to_host(T value) { return be32toh(value); }
};

template<class T>
struct byte_order_converter<T, 8>
{
    static T host_to_network(T value) { return htobe64(value); }
    static T network_to_host(T value) { return be64toh(value); }
};

template<class T>
struct byte_order_converter<T, 16>
{
    union mask128 {
        mask128(T t) : value(t) {}
        T value;
        uint64_t part[2];
    };

    static T host_to_network(mask128 in) {
        mask128 out(0);
        out.part[1] = byte_order_converter<uint64_t>::host_to_network(in.part[0]);
        out.part[0] = byte_order_converter<uint64_t>::host_to_network(in.part[1]);
        return out.value;
    }

    static T network_to_host(mask128 in) {
        mask128 out(0);
        out.part[1] = byte_order_converter<uint64_t>::network_to_host(in.part[0]);
        out.part[0] = byte_order_converter<uint64_t>::network_to_host(in.part[1]);
        return out.value;
    }
};

} // namespace detail


template<class T>
T hton(T host_value)
{
    return detail::byte_order_converter<T>::host_to_network(host_value);
}

template<class T>
T ntoh(T network_value)
{
    return detail::byte_order_converter<T>::network_to_host(network_value);
}


enum class ByteOrder {
    BigEndian,
    LittleEndian
};


namespace detail
{

#if BYTE_ORDER == LITTLE_ENDIAN
    static const ByteOrder host_byte_order = ByteOrder::LittleEndian;
#elif BYTE_ORDER == BIG_ENDIAN
    static const ByteOrder host_byte_order = ByteOrder::BigEndian;
#else
#   error "Unknown byte order"
#endif

} // namespace detail

constexpr ByteOrder getHostByteOrder() { return detail::host_byte_order; }

template<typename T, ByteOrder ORDER = getHostByteOrder()>
class EndianType;

/**
 * Explicitly forge a plain type to an EndianType.
 * It is assumed the passed value is already in the stated byte order,
 * i.e. endian_cast does _not_ trigger any automatic conversions.
 * \param value A plain value in byte order ORDER
 * \return EndianType capable to carry value type
 */
template<ByteOrder ORDER, typename T>
EndianType<T, ORDER> endian_cast(T value)
{
    return static_cast< EndianType<T, ORDER> >(value);
}

/**
 * Cast POD type to EndianType in host byte order
 * \param value POD in host byte order
 * \return EndianType carrying value
 */
template<typename T>
EndianType<T, getHostByteOrder()> host_cast(T value)
{
    return endian_cast<getHostByteOrder()>(value);
}

/**
 * Cast POD type to EndianType in network byte order
 * \param value POD in network byte order
 * \return EndianType carrying value
 */
template<typename T>
EndianType<T, ByteOrder::BigEndian> network_cast(T value)
{
    return endian_cast<ByteOrder::BigEndian>(value);
}


namespace detail
{

template<typename T>
class EndianTypeStorage
{
    static_assert(std::is_pod<T>::value == true, "EndianType is only availabe for POD types");

public:
    typedef T value_type;

    EndianTypeStorage() = default;
    explicit EndianTypeStorage(T value) : mValue(value) {}

    void set(T value) { mValue = value; }
    T get() const { return mValue; }
    explicit operator T() const { return get(); }

protected:
    T mValue;
};


template<typename T, typename BASE>
class EndianTypeCasterToHost : public BASE
{
public:
    typedef EndianType<T, getHostByteOrder()> host_type;
    operator host_type() const { return host_cast(ntoh(BASE::get())); }
};

template<typename T, typename BASE>
class EndianTypeCasterToNetwork : public BASE
{
public:
    typedef EndianType<T, ByteOrder::BigEndian> network_type;
    operator network_type() const { return network_cast(hton(BASE::get())); }
};


template<typename T, typename BASE, ByteOrder ORDER, bool HOST_EQ_NET = (getHostByteOrder() == ByteOrder::BigEndian)>
class EndianTypeCaster;

template<typename T, typename BASE, ByteOrder ORDER>
class EndianTypeCaster<T, BASE, ORDER, true> : public BASE {};

template<typename T, typename BASE, ByteOrder ORDER>
class EndianTypeCaster<T, BASE, ORDER, false> : public
    std::conditional<ORDER == ByteOrder::BigEndian,
        EndianTypeCasterToHost<T, BASE>,
        EndianTypeCasterToNetwork<T, BASE>
    >::type {};

} // namespace detail


template<typename T, ByteOrder ORDER>
class EndianType : public detail::EndianTypeCaster<T, detail::EndianTypeStorage<T>, ORDER>
{
public:
    typedef detail::EndianTypeStorage<T> storage_type;
    typedef detail::EndianTypeCaster<T, storage_type, ORDER> base_type;
    typedef EndianType<T, getHostByteOrder()> host_type;
    typedef EndianType<T, ByteOrder::BigEndian> network_type;

    EndianType() = default;
    explicit EndianType(T value) { storage_type::set(value); }

    bool operator==(const EndianType& other) const
    {
        return base_type::get() == other.get();
    }

    bool operator!=(const EndianType& other) const
    {
        return !(*this == other);
    }

    T net() const
    {
        return network_type(*this).get();
    }

    T host() const
    {
        return host_type(*this).get();
    }
};


/**
 * Print to ostream in network byte order
 * \param os output stream
 * \param t endian type object
 * \return os
 */
template<typename T, ByteOrder ORDER>
std::ostream& operator<<(std::ostream& os, const EndianType<T, ORDER>& t)
{
    os << t.net();
    return os;
}

typedef EndianType<uint8_t, ByteOrder::BigEndian> uint8be_t;
typedef EndianType<uint16_t, ByteOrder::BigEndian> uint16be_t;
typedef EndianType<uint32_t, ByteOrder::BigEndian> uint32be_t;
typedef EndianType<uint64_t, ByteOrder::BigEndian> uint64be_t;

typedef EndianType<int8_t, ByteOrder::BigEndian> int8be_t;
typedef EndianType<int16_t, ByteOrder::BigEndian> int16be_t;
typedef EndianType<int32_t, ByteOrder::BigEndian> int32be_t;
typedef EndianType<int64_t, ByteOrder::BigEndian> int64be_t;

} // namespace vanetza

namespace std
{

template<typename T, vanetza::ByteOrder ORDER>
struct hash<vanetza::EndianType<T, ORDER>>
{
    size_t operator()(const vanetza::EndianType<T, ORDER>& t) const
    {
        return hash<T>()(t.get());
    }
};

} // namespace std

#endif /* BYTE_ORDER_HPP_LPUJ094I */

