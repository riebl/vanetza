#include "asn1.hpp"
#include "exception.hpp"
#include "keys.hpp"
#include "sha.hpp"
#include <vanetza/asn1/security/EtsiTs103097Data.h>
#include <vanetza/asn1/support/OCTET_STRING.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace vanetza
{
namespace pki
{

ByteBuffer copy(const OCTET_STRING_t& octets)
{
    ByteBuffer buffer(octets.size);
    std::memcpy(buffer.data(), octets.buf, octets.size);
    return buffer;
}

const OCTET_STRING_t* get_signed_payload(const Vanetza_Security_Ieee1609Dot2Content_t* content)
{
    const OCTET_STRING_t* payload = nullptr;
    if (content && content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        const Vanetza_Security_SignedData_t* data = content->choice.signedData;
        if (data && data->tbsData && data->tbsData->payload) {
            const Vanetza_Security_SignedDataPayload_t& spayload = *data->tbsData->payload;
            if (spayload.data && spayload.data->content &&
                spayload.data->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData) {
                payload = &spayload.data->content->choice.unsecuredData;
            }
        }
    }

    return payload;
}

bool MgmtData::decode(const Vanetza_Security_Opaque_t& opaque)
{
    return wrapper::decode(opaque.buf, opaque.size);
}

MgmtData MgmtData::decode_expecting(const void* buffer, std::size_t size,
    Vanetza_Security_EtsiTs102941DataContent_PR expected)
{
    MgmtData mgmt;
    if (!mgmt.decode(buffer, size)) {
        throw DecodingFailure("decoding management data failed");
    }
    if (mgmt->content.present != expected) {
        throw DecodingFailure("management data contains unexpected content");
    }
    return mgmt;
}

MgmtData MgmtData::decode_expecting(const Vanetza_Security_Opaque_t& opaque,
    Vanetza_Security_EtsiTs102941DataContent_PR expected)
{
    return decode_expecting(opaque.buf, opaque.size, expected);
}

TlmCtlData TlmCtlData::from_buffer(const void* buffer, std::size_t size)
{
    return TlmCtlData { decode_expecting(buffer, size,
        Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListTlm) };
}

TlmCtlData TlmCtlData::from_opaque(const Vanetza_Security_Opaque_t& opaque)
{
    return from_buffer(opaque.buf, opaque.size);
}

RcaCtlData RcaCtlData::from_buffer(const void* buffer, std::size_t size)
{
    return RcaCtlData { decode_expecting(buffer, size,
        Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListRca) };
}

RcaCtlData RcaCtlData::from_opaque(const Vanetza_Security_Opaque_t& opaque)
{
    return from_buffer(opaque.buf, opaque.size);
}

EnrolmentResponseData EnrolmentResponseData::from_buffer(const void* buffer, std::size_t size)
{
    return EnrolmentResponseData { decode_expecting(buffer, size,
        Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentResponse) };
}

EnrolmentResponseData EnrolmentResponseData::from_opaque(const Vanetza_Security_Opaque_t& opaque)
{
    return from_buffer(opaque.buf, opaque.size);
}

AuthorizationResponseData AuthorizationResponseData::from_buffer(const void* buffer, std::size_t size)
{
    return AuthorizationResponseData { decode_expecting(buffer, size,
        Vanetza_Security_EtsiTs102941DataContent_PR_authorizationResponse) };
}

AuthorizationResponseData AuthorizationResponseData::from_opaque(const Vanetza_Security_Opaque_t& opaque)
{
    return from_buffer(opaque.buf, opaque.size);
}

void copy(const OCTET_STRING_t& src, ByteBuffer& dst)
{
    static_assert(sizeof(ByteBuffer::value_type) == sizeof(char), "sizes do not match");

    dst.resize(src.size);
    std::copy_n(src.buf, src.size, dst.data());
}

void copy(const ByteBuffer& src, OCTET_STRING_t& dst)
{
    static_assert(sizeof(ByteBuffer::value_type) == sizeof(char), "sizes do not match");

    auto src_buf = reinterpret_cast<const char*>(src.data());
    if (OCTET_STRING_fromBuf(&dst, src_buf, src.size()) != 0) {
        throw std::runtime_error("copying buffer into OCTET_STRING failed");
    }
}

void copy_left_padded(const ByteBuffer& src, OCTET_STRING_t& dst, std::size_t len)
{
    static_assert(sizeof(ByteBuffer::value_type) == sizeof(char), "sizes do not match");

    if (src.size() > len) {
        throw std::runtime_error("source bytes exceed desired length of destination buffer");
    } else if (src.size() == len) {
        copy(src, dst);
        assert(dst.size == len);
    } else {
        std::string tmp;
        tmp.assign(len, '\0');
        std::copy(src.begin(), src.end(), std::next(tmp.begin(), len - src.size()));
        if (OCTET_STRING_fromBuf(&dst, tmp.data(), tmp.size()) != 0) {
            throw std::runtime_error("copying buffer into OCTET_STRING failed");
        }
    }
}

void fill_curve_point(const PublicKey& key, Vanetza_Security_EccP256CurvePoint_t& point)
{
    switch (key.compression) {
        case KeyCompression::NoCompression:
            point.present = Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256;
            copy_left_padded(key.x, point.choice.uncompressedP256.x, 32);
            copy_left_padded(key.y, point.choice.uncompressedP256.y, 32);
            break;
        case KeyCompression::Y0:
            point.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0;
            copy_left_padded(key.x, point.choice.compressed_y_0, 32);
            break;
        case KeyCompression::Y1:
            point.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1;
            copy_left_padded(key.x, point.choice.compressed_y_1, 32);
            break;
        default:
            throw std::invalid_argument("unknown key compression");
    }
}

void fill_curve_point(const PublicKey& key, Vanetza_Security_EccP384CurvePoint_t& point)
{
    switch (key.compression) {
        case KeyCompression::NoCompression:
            point.present = Vanetza_Security_EccP384CurvePoint_PR_uncompressedP384;
            copy_left_padded(key.x, point.choice.uncompressedP384.x, 48);
            copy_left_padded(key.y, point.choice.uncompressedP384.y, 48);
            break;
        case KeyCompression::Y0:
            point.present = Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0;
            copy_left_padded(key.x, point.choice.compressed_y_0, 48);
            break;
        case KeyCompression::Y1:
            point.present = Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1;
            copy_left_padded(key.x, point.choice.compressed_y_1, 48);
            break;
        default:
            throw std::invalid_argument("unknown key compression");
    }
}

Vanetza_Security_HashAlgorithm_t convert(HashAlgorithm from)
{
    switch (from) {
        case HashAlgorithm::SHA256:
            return Vanetza_Security_HashAlgorithm_sha256;
            break;
        case HashAlgorithm::SHA384:
            return Vanetza_Security_HashAlgorithm_sha384;
            break;
        default:
            throw std::invalid_argument("unknown hash algorithm");
    }
}

ByteBuffer to_buffer(const OCTET_STRING_t& input)
{
    return ByteBuffer { input.buf, input.buf + input.size };
}

std::string to_string(const OCTET_STRING_t& input)
{
    if (input.buf) {
        return std::string { reinterpret_cast<const char*>(input.buf), input.size };
    } else {
        return std::string {};
    }
}

bool operator==(const OCTET_STRING_t& lhs, const ByteBuffer& rhs)
{
    if (lhs.size == rhs.size()) {
        if (std::memcmp(lhs.buf, rhs.data(), lhs.size) == 0) {
            return true;
        }
    }
    return false;
}

bool operator!=(const OCTET_STRING_t& lhs, const ByteBuffer& rhs)
{
    return !(lhs == rhs);
}

bool operator==(const ByteBuffer& lhs, const OCTET_STRING_t& rhs)
{
    return rhs == lhs;
}

bool operator!=(const ByteBuffer& lhs, const OCTET_STRING_t& rhs)
{
    return !(rhs == lhs);
}

} // namespace pki
} // namespace vanetza
