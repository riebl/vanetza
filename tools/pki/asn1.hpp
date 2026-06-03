#pragma once

#include "keys.hpp"
#include "sha.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/common/byte_buffer.hpp>
#include <cstring>

// forward declaration
typedef struct OCTET_STRING OCTET_STRING_t;

namespace vanetza
{
namespace pki
{

ByteBuffer copy(const OCTET_STRING_t&);
const OCTET_STRING_t* get_signed_payload(const Vanetza_Security_Ieee1609Dot2Content_t*);

class MgmtData : public asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t>
{
public:
    using wrapper = asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t>;

    MgmtData() : asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t>(asn_DEF_Vanetza_Security_EtsiTs102941Data)
    {
    }

    using wrapper::decode;
    bool decode(const Vanetza_Security_Opaque_t&);

protected:
    /**
     * Decode and assert the content variant matches `expected`.
     *
     * \throws DecodingFailure on decode failure or unexpected content variant
     */
    static MgmtData decode_expecting(const void* buffer, std::size_t size,
        Vanetza_Security_EtsiTs102941DataContent_PR expected);
    static MgmtData decode_expecting(const Vanetza_Security_Opaque_t&,
        Vanetza_Security_EtsiTs102941DataContent_PR expected);
};

// Management data known to carry a TLM certificate trust list.
class TlmCtlData : public MgmtData
{
public:
    TlmCtlData() = default;

    static TlmCtlData from_buffer(const void* buffer, std::size_t size);
    static TlmCtlData from_opaque(const Vanetza_Security_Opaque_t&);

private:
    explicit TlmCtlData(MgmtData&& base) : MgmtData(std::move(base))
    {
    }
};

// Management data known to carry an RCA certificate trust list.
class RcaCtlData : public MgmtData
{
public:
    RcaCtlData() = default;

    static RcaCtlData from_buffer(const void* buffer, std::size_t size);
    static RcaCtlData from_opaque(const Vanetza_Security_Opaque_t&);

private:
    explicit RcaCtlData(MgmtData&& base) : MgmtData(std::move(base))
    {
    }
};

// Management data known to carry an enrolment response.
class EnrolmentResponseData : public MgmtData
{
public:
    EnrolmentResponseData() = default;

    static EnrolmentResponseData from_buffer(const void* buffer, std::size_t size);
    static EnrolmentResponseData from_opaque(const Vanetza_Security_Opaque_t&);

private:
    explicit EnrolmentResponseData(MgmtData&& base) : MgmtData(std::move(base))
    {
    }
};

// Management data known to carry an authorization response.
class AuthorizationResponseData : public MgmtData
{
public:
    AuthorizationResponseData() = default;

    static AuthorizationResponseData from_buffer(const void* buffer, std::size_t size);
    static AuthorizationResponseData from_opaque(const Vanetza_Security_Opaque_t&);

private:
    explicit AuthorizationResponseData(MgmtData&& base) : MgmtData(std::move(base))
    {
    }
};

void fill_curve_point(const PublicKey&, Vanetza_Security_EccP256CurvePoint_t&);
void fill_curve_point(const PublicKey&, Vanetza_Security_EccP384CurvePoint_t&);

void copy(const OCTET_STRING_t& src, ByteBuffer& dst);
void copy(const ByteBuffer& src, OCTET_STRING_t& dst);
void copy_left_padded(const ByteBuffer& src, OCTET_STRING_t& dst, std::size_t len);

Vanetza_Security_HashAlgorithm_t convert(HashAlgorithm);
ByteBuffer to_buffer(const OCTET_STRING_t&);

std::string to_string(const OCTET_STRING_t&);

/**
 * \brief strong-typed wrapper around asn1c-generated enum
 * 
 * \tparam Tag generated C enum
 * \tparam T underlying type
 */
template<typename Tag, typename T = long> struct asn1c_enum
{
    T value;
    constexpr explicit asn1c_enum(T v = T {}) : value(v)
    {
    }
};

template<typename Tag, typename T> constexpr bool operator==(asn1c_enum<Tag, T> l, asn1c_enum<Tag, T> r)
{
    return l.value == r.value;
}

template<typename Tag, typename T> constexpr bool operator!=(asn1c_enum<Tag, T> l, asn1c_enum<Tag, T> r)
{
    return l.value != r.value;
}

template<typename Tag, typename T> constexpr bool operator==(asn1c_enum<Tag, T> l, Tag r)
{
    return l.value == static_cast<T>(r);
}

template<typename Tag, typename T> constexpr bool operator!=(asn1c_enum<Tag, T> l, Tag r)
{
    return l.value != static_cast<T>(r);
}

template<typename Tag, typename T> constexpr bool operator==(Tag l, asn1c_enum<Tag, T> r)
{
    return static_cast<T>(l) == r.value;
}

template<typename Tag, typename T> constexpr bool operator!=(Tag l, asn1c_enum<Tag, T> r)
{
    return static_cast<T>(l) != r.value;
}

bool operator==(const OCTET_STRING_t&, const ByteBuffer&);
bool operator!=(const OCTET_STRING_t&, const ByteBuffer&);
bool operator==(const ByteBuffer&, const OCTET_STRING_t&);
bool operator!=(const ByteBuffer&, const OCTET_STRING_t&);

template<std::size_t N> bool operator==(const OCTET_STRING_t& lhs, const std::array<std::uint8_t, N>& rhs)
{
    return lhs.size == N && std::memcmp(lhs.buf, rhs.data(), N) == 0;
}

template<std::size_t N> bool operator!=(const OCTET_STRING_t& lhs, const std::array<std::uint8_t, N>& rhs)
{
    return !(lhs == rhs);
}

template<std::size_t N> bool operator==(const std::array<std::uint8_t, N>& lhs, const OCTET_STRING_t& rhs)
{
    return rhs == lhs;
}

template<std::size_t N> bool operator!=(const std::array<std::uint8_t, N>& lhs, const OCTET_STRING_t& rhs)
{
    return !(rhs == lhs);
}

} // namespace pki
} // namespace vanetza
