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

struct Sha256Hmac
{
    static constexpr std::size_t length = 32;
    std::array<std::uint8_t, length> octets;
};

bool operator==(const Sha256Hmac& lhs, const Sha256Hmac& rhs);
bool operator!=(const Sha256Hmac& lhs, const Sha256Hmac& rhs);

struct KeyTag
{
    static constexpr std::size_t length = 16;
    std::array<std::uint8_t, length> octets;

    KeyTag() = default;

    /**
     * Truncate HMAC to its leftmost 128 bits (ETSI TS 102 941 §6.2.3.3.1)
     */
    explicit KeyTag(const Sha256Hmac& hmac);
};

bool operator==(const KeyTag& lhs, const KeyTag& rhs);
bool operator!=(const KeyTag& lhs, const KeyTag& rhs);

/**
 * \brief generate HMAC key and create HMAC tag on data
 * \deprecated use SecurityModule::calculate_hmac_sha256 and KeyTag(const Sha256Hmac&) instead,
 *             this function picks its backend at compile time and cannot report failures
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
