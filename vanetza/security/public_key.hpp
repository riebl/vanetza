#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/key_type.hpp>
#include <string>

namespace vanetza
{
namespace security
{

enum class KeyCompression
{
    NoCompression,
    Y0,
    Y1
};

struct PublicKey
{
    ByteBuffer x;
    ByteBuffer y;
    KeyType type;
    KeyCompression compression;
};

/**
 * Compute canonical hex string of a compressed public key.
 * \return hex string, or empty string if the key is malformed
 */
std::string canonical_hexstring(const PublicKey&);

} // namespace security
} // namespace vanetza
