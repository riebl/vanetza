#pragma once

#include "security_module.hpp"
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace pki
{

class CredentialStorage;

class OpenSslSecurityModule : public SecurityModule
{
public:
    OpenSslSecurityModule(std::shared_ptr<CredentialStorage>);

    Sha256Hash calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length) override;
    Sha384Hash calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length) override;
    bool verify(const Sha256Hash&, const Signature&, const PublicKey&) override;
    bool verify(const Sha384Hash&, const Signature&, const PublicKey&) override;
    ByteBuffer generate_nonce(std::size_t length) override;
    std::unique_ptr<EciesContext> create_ecies_context(const PublicKey& receiver, const Sha256Hash& info) override;
    ByteBuffer calculate_hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) override;

    boost::optional<Signature> sign(const ByteBuffer& data, const PublicKey&) override;

    /**
     * Creates a new public and private key pair.
     * The private key is intentionally not returned but only stored in the credential storage.
     */
    PublicKey create_key(KeyType) override;

    bool discard_key(const PublicKey&) override;

private:
    bool verify(const uint8_t* digest, std::size_t dlen, const Signature&, const PublicKey&);
    boost::optional<Signature> sign(const ByteBuffer&, const PrivateKey&);

    std::shared_ptr<CredentialStorage> m_credential_storage;
};

} // namespace pki
} // namespace vanetza
