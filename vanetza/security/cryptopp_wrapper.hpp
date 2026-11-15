#pragma once

#include <vanetza/security/key_type.hpp>
#include <vanetza/security/public_key.hpp>
#include <boost/optional/optional.hpp>
#include <cryptopp/eccrypto.h>

namespace vanetza
{
namespace security
{
namespace cryptopp
{

using EcPublicKey = CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>;

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

} // namespace cryptopp
} // namespace security
} // namespace vanetza
