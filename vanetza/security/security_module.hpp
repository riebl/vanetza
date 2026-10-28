#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/signature.hpp>
#include <boost/optional/optional.hpp>
#include <memory>

namespace vanetza
{
namespace security
{

class SecurityModule
{
public:
    class EciesContext
    {
    public:
        virtual ~EciesContext() = default;
        virtual PublicKey ephemeral_public_key() const = 0;
        virtual PublicKey recipient_public_key() const = 0;
        virtual ByteBuffer shared_secret() const = 0;
        virtual ByteBuffer encrypted_key() const = 0;
        virtual ByteBuffer authentication_tag() const = 0;
        virtual ByteBuffer nonce() const = 0;
        virtual void nonce(const ByteBuffer&) = 0;

        virtual ByteBuffer encrypt(const ByteBuffer& plaintext) = 0;
        virtual ByteBuffer decrypt(const std::uint8_t* buffer, std::size_t length) = 0;
    };

    virtual ~SecurityModule() = default;
    virtual Sha256Hash calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length) = 0;
    virtual Sha384Hash calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length) = 0;
    virtual bool verify(const Sha256Hash&, const Signature&, const PublicKey&) = 0;
    virtual bool verify(const Sha384Hash&, const Signature&, const PublicKey&) = 0;

    virtual boost::optional<Signature> sign(const ByteBuffer& digest, const PublicKey&) = 0;

    // True if the private key matching `key` is available for signing.
    virtual bool can_sign(const PublicKey& key);

    virtual PublicKey create_key(KeyType) = 0;
    virtual bool discard_key(const PublicKey&) = 0;

    virtual ByteBuffer generate_nonce(std::size_t length) = 0;
    virtual std::unique_ptr<EciesContext> create_ecies_context(const PublicKey& receiver, const Sha256Hash& info) = 0;
    virtual ByteBuffer calculate_hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) = 0;
};

} // namespace security
} // namespace vanetza
