#pragma once

#include <vanetza/security/aes.hpp>
#include <vanetza/security/hmac.hpp>
#include <vanetza/security/public_key.hpp>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

/**
 * AES-128 key encrypted for a recipient by ECIES as specified by IEEE 1609.2
 */
struct EncryptedSymmetricKey
{
    PublicKey public_key; // sender's ephemeral public key
    KeyTag authentication_tag;
    std::array<std::uint8_t, Aes128Key::length> wrapped_key; // XOR encryption keeps length of key
};

} // namespace security
} // namespace vanetza
