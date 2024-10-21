#include <vanetza/security/backend.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/hash.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

ByteBuffer calculate_message_hash(Backend& backend, HashAlgorithm hash_algo, const ByteBuffer& payload, const CertificateView& signing_cert)
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

    ByteBuffer data_hash = backend.calculate_hash(hash_algo, payload);
    ByteBuffer cert_hash = backend.calculate_hash(hash_algo, encoded_cert);
    ByteBuffer concat_hash;
    concat_hash.reserve(data_hash.size() + cert_hash.size());
    concat_hash.insert(concat_hash.end(), data_hash.begin(), data_hash.end());
    concat_hash.insert(concat_hash.end(), cert_hash.begin(), cert_hash.end());
    return backend.calculate_hash(hash_algo, concat_hash);
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
