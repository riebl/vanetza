#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <array>
#include <cstddef>
#include <cstdint>

namespace vanetza
{
namespace security
{

/**
 * AES-128 key residing in host memory
 *
 * The C2C-CC Protection Profile V2X HSM (BSI-CC-PP-0114, PP_HSM_202) lets the host
 * generate session keys and run AES while the HSM only encrypts session keys by ECIES.
 */
struct Aes128Key
{
    static constexpr std::size_t length = 16;
    std::array<std::uint8_t, length> octets;

    ~Aes128Key();
};

bool operator==(const Aes128Key& lhs, const Aes128Key& rhs);
bool operator!=(const Aes128Key& lhs, const Aes128Key& rhs);

/**
 * AES-CCM encrypted data as specified by IEEE 1609.2
 */
struct AesCcmCiphertext
{
    static constexpr std::size_t nonce_length = 12;
    std::array<std::uint8_t, nonce_length> nonce;
    ByteBuffer ciphertext; // including authentication tag
};

} // namespace security
} // namespace vanetza
