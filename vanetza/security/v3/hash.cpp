#include <vanetza/security/backend.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/hash.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

// signer's certificate is hashed in canonical form
ByteBuffer encode_signing_certificate(const CertificateView& signing_cert)
{
    ByteBuffer encoded_cert;
    if (signing_cert.is_canonical()) {
        encoded_cert = signing_cert.encode();
    } else {
        auto canonical_signing_cert = signing_cert.canonicalize();
        if (canonical_signing_cert) {
            encoded_cert = canonical_signing_cert->encode();
        }
    }
    return encoded_cert;
}

// Hash(Hash(data) || Hash(signer))
template<typename HashFn>
ByteBuffer combine_hashes(HashFn hash, const ByteBuffer& payload, const ByteBuffer& encoded_cert)
{
    const auto data_hash = hash(payload);
    const auto cert_hash = hash(encoded_cert);
    ByteBuffer concat_hash;
    concat_hash.reserve(data_hash.size() + cert_hash.size());
    concat_hash.insert(concat_hash.end(), data_hash.begin(), data_hash.end());
    concat_hash.insert(concat_hash.end(), cert_hash.begin(), cert_hash.end());
    const auto message_hash = hash(concat_hash);
    return ByteBuffer(message_hash.begin(), message_hash.end());
}

} // namespace

ByteBuffer calculate_message_hash(Backend& backend, HashAlgorithm hash_algo, const ByteBuffer& payload, const CertificateView& signing_cert)
{
    const ByteBuffer encoded_cert = encode_signing_certificate(signing_cert);
    return combine_hashes([&backend, hash_algo](const ByteBuffer& data) {
        return backend.calculate_hash(hash_algo, data);
    }, payload, encoded_cert);
}

ByteBuffer calculate_message_hash(CryptoProvider& crypto, HashAlgorithm hash_algo, const ByteBuffer& payload,
    const CertificateView& signing_cert)
{
    const ByteBuffer encoded_cert = encode_signing_certificate(signing_cert);
    switch (hash_algo) {
        case HashAlgorithm::SHA256:
            return combine_hashes([&crypto](const ByteBuffer& data) {
                return crypto.calculate_sha256_hash(data.data(), data.size()).octets;
            }, payload, encoded_cert);
        case HashAlgorithm::SHA384:
            return combine_hashes([&crypto](const ByteBuffer& data) {
                return crypto.calculate_sha384_hash(data.data(), data.size()).octets;
            }, payload, encoded_cert);
        default:
            return ByteBuffer();
    }
}

HashAlgorithm specified_hash_algorithm(KeyType key_type)
{
    switch (key_type) {
        case KeyType::NistP256:
        case KeyType::BrainpoolP256r1:
            return HashAlgorithm::SHA256;
        case KeyType::BrainpoolP384r1:
            return HashAlgorithm::SHA384;
        default:
            return HashAlgorithm::Unspecified;
    }
}

} // namespace v3
} // namespace security
} // namespace vanetza
