#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <array>
#include <cstddef>
#include <cstdint>

namespace vanetza
{
namespace security
{

struct HmacKey
{
    static constexpr std::size_t length = 32;
    std::array<std::uint8_t, length> octets;

    ~HmacKey();
};

bool operator==(const HmacKey& lhs, const HmacKey& rhs);
bool operator!=(const HmacKey& lhs, const HmacKey& rhs);

using KeyTag = std::array<uint8_t, 16>;

/**
 * \brief generate HMAC key and create HMAC tag on data
 * \param data data to be tagged
 * \param hmacKey generated HMAC key
 * \return tag of data generated with hmacKey
*/
KeyTag create_hmac_tag(const vanetza::ByteBuffer& data, const HmacKey& hmacKey);

#if defined VANETZA_WITH_OPENSSL
KeyTag create_hmac_tag_openssl(const vanetza::ByteBuffer& data, const HmacKey& hmacKey);
#endif

#if defined VANETZA_WITH_CRYPTOPP
KeyTag create_hmac_tag_cryptopp(const vanetza::ByteBuffer& data, const HmacKey& hmacKey);
#endif

} // namespace security
} // namespace vanetza
