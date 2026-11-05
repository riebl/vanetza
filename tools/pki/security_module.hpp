#pragma once

#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/scoped_key_pair.hpp>
#include <vanetza/security/security_module.hpp>

namespace vanetza
{
namespace pki
{

using security::AesCcmCiphertext;
using security::CryptoProvider;
using security::EncryptedSymmetricKey;
using security::ScopedKeyPair;
using security::SecurityModule;

} // namespace pki
} // namespace vanetza
