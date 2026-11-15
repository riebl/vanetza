#pragma once

#include <vanetza/security/key_type.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/public_key.hpp>
#include <boost/optional/optional.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/integer.h>
#include <cstddef>
#include <cstdint>

namespace vanetza
{
namespace security
{
namespace cryptopp
{

using EcPublicKey = CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>;
using EcPrivateKey = CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>;

/**
 * Derive Crypto++ OID object from key type
 * \param key_type key type from our API
 * \return Crypto++ OID object (possibly empty)
 */
CryptoPP::OID get_oid(KeyType key_type);

/**
 * Convert our PublicKey type to a Crypto++ EC public key
 * \param pub_key our public key
 * \return public key as Crypto++ type (if conversion was possible)
 */
boost::optional<EcPublicKey> convert_public_key(const PublicKey& pub_key);

/**
 * Convert our PrivateKey type to a Crypto++ EC private key
 * \param priv_key our private key
 * \return private key as Crypto++ type
 */
EcPrivateKey convert_private_key(const PrivateKey& priv_key);

/**
 * Fill a buffer with random octets of the operating system
 * \return false if no random octets are available
 */
bool generate_random(std::uint8_t* buffer, std::size_t length);

/**
 * Integer of a digest signed by ECDSA, i.e. its leftmost bits up to the bit length of the group order
 * \param digest hash value
 * \param length octets of digest
 * \param order order of the curve's group
 * \return integer of digest
 */
CryptoPP::Integer digest_integer(const std::uint8_t* digest, std::size_t length, const CryptoPP::Integer& order);

} // namespace cryptopp
} // namespace security
} // namespace vanetza
