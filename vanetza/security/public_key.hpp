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

/**
 * Encode public key as elliptic curve point according to SEC 1 v2, section 2.3.3
 *
 * The key's coordinates are big-endian integers, which are encoded with exactly the curve's field length,
 * i.e. leading zero octets are added or stripped as needed. The key's compression form is kept.
 * \return 0x04 || x || y (uncompressed) or 0x02/0x03 || x (compressed), or empty buffer if the key is malformed
 */
ByteBuffer encode_ec_point(const PublicKey&);

/**
 * Encode public key as SubjectPublicKeyInfo according to RFC 5480.
 * \return DER-encoded SubjectPublicKeyInfo, or empty buffer if the key is malformed
 */
ByteBuffer encode_subject_public_key_info(const PublicKey&);

} // namespace security
} // namespace vanetza
