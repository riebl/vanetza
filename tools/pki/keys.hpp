#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>

// forward declarations
struct Vanetza_Security_Signature;
struct Vanetza_Security_PublicVerificationKey;
struct Vanetza_Security_PublicEncryptionKey;

namespace vanetza
{
namespace pki
{

using security::KeyCompression;
using security::KeyType;
using security::PrivateKey;
using security::PublicKey;
using security::Signature;

PublicKey derive_public_key(const PrivateKey&);
Signature make_signature(const struct Vanetza_Security_Signature&);

/**
 * Generate a fresh random EC private key on the curve matching `type`.
 *
 * \throws OpenSslException on generation failure
 */
PrivateKey generate_private_key(KeyType type);

/**
 * Populate an ASN.1 PublicVerificationKey CHOICE from a PublicKey.
 *
 * \throws std::invalid_argument on unsupported key types
 */
void set_verification_key(struct Vanetza_Security_PublicVerificationKey&, const PublicKey&);

/**
 * Populate an ASN.1 PublicEncryptionKey from a PublicKey.
 * Sets supportedSymmAlg to AES-128-CCM.
 *
 * \throws std::invalid_argument on unsupported key types
 */
void set_encryption_key(struct Vanetza_Security_PublicEncryptionKey&, const PublicKey&);

} // namespace pki
} // namespace vanetza
