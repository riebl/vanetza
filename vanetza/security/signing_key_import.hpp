#pragma once
#include <vanetza/common/expected.hpp>
#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/private_key.hpp>

namespace vanetza
{
namespace security
{

/**
 * Feature of security modules importing existing private keys, e.g. to migrate key files of former versions
 */
class SigningKeyImport
{
public:
    /**
     * Import a private key, it is stored permanently as far as the module stores keys
     * \param key private key
     * \return reference to imported key or error, e.g. UnsupportedKeyType or InvalidPrivateKey
     */
    virtual expected<KeyReference> import_signing_key(const PrivateKey& key) = 0;

protected:
    ~SigningKeyImport() = default;
};

} // namespace security
} // namespace vanetza
