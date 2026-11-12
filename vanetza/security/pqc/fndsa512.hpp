#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/expected.hpp>
#include <vanetza/security/key_reference.hpp>
#include <cstddef>
#include <memory>

namespace vanetza
{
namespace security
{
namespace pqc
{

constexpr std::size_t fndsa512_public_key_size = 897;
constexpr std::size_t fndsa512_private_key_size = 1281;
constexpr std::size_t fndsa512_signature_size = 666;

struct PublicKey
{
    ByteBuffer bytes;
};

/** \deprecated exposes private key, use KeyReference */
struct PrivateKey
{
    ByteBuffer bytes;
};

struct Signature
{
    ByteBuffer bytes;
};

/** \deprecated exposes private key, use SigningKey */
struct KeyPair
{
    PublicKey public_key;
    PrivateKey private_key;
};

/** Private key held by a Backend and its public key */
struct SigningKey
{
    KeyReference reference;
    PublicKey public_key;
};

/**
 * Cryptographic operations for the experimental FN-DSA-512 profile.
 *
 * The interface is intentionally separate from security::Backend. Enabling
 * the experimental profile therefore does not alter the established ECC
 * backend contract or its key types.
 */
class Backend
{
public:
    /** \deprecated exposes private key, use create_signing_key() */
    virtual KeyPair generate_key_pair() = 0;
    /** \deprecated exposes private key, use sign(const KeyReference&, const ByteBuffer&) */
    virtual Signature sign(const PrivateKey&, const ByteBuffer& data) = 0;
    virtual bool verify(const PublicKey&, const ByteBuffer& data, const Signature&) = 0;

    /**
     * Create a key pair for signing
     * \return reference to created private key and its public key or error, see SecurityModuleError for conditions
     */
    virtual expected<SigningKey> create_signing_key() = 0;

    /**
     * Sign data
     * \param key reference to private key
     * \param data data to sign
     * \return signature or error, see SecurityModuleError for conditions
     */
    virtual expected<Signature> sign(const KeyReference& key, const ByteBuffer& data) = 0;

    virtual ~Backend() = default;
};

/**
 * Create the liboqs-backed implementation used by the experimental profile.
 */
std::unique_ptr<Backend> create_fndsa512_backend();

} // namespace pqc
} // namespace security
} // namespace vanetza
