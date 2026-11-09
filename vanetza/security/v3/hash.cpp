#include <vanetza/security/backend.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

// signer's certificate is hashed in canonical form, empty if it has none or its encoding fails (see error)
ByteBuffer encode_signing_certificate(const CertificateView& signing_cert, vanetza::asn1::asn1c_error& error)
{
    error = vanetza::asn1::asn1c_error();
    if (signing_cert.is_canonical()) {
        return signing_cert.encode(error);
    } else {
        const boost::optional<Certificate> canonical = signing_cert.canonicalize();
        return canonical ? canonical->encode(error) : ByteBuffer {};
    }
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
    vanetza::asn1::asn1c_error error;
    const ByteBuffer encoded_cert = encode_signing_certificate(signing_cert, error);
    if (error) {
        throw vanetza::asn1::asn1c_exception(error);
    }
    return combine_hashes([&backend, hash_algo](const ByteBuffer& data) {
        return backend.calculate_hash(hash_algo, data);
    }, payload, encoded_cert);
}

ByteBuffer calculate_message_hash(CryptoProvider& crypto, HashAlgorithm hash_algo, const ByteBuffer& payload,
    const CertificateView& signing_cert)
{
    vanetza::asn1::asn1c_error error;
    const ByteBuffer encoded_cert = encode_signing_certificate(signing_cert, error);
    if (encoded_cert.empty()) {
        return ByteBuffer {};
    }
    // calculate_hash is empty for an unsupported algorithm, thus is the combined hash
    return combine_hashes([&crypto, hash_algo](const ByteBuffer& data) {
        return calculate_hash(crypto, hash_algo, data);
    }, payload, encoded_cert);
}

ByteBuffer calculate_certificate_hash(CryptoProvider& crypto, HashAlgorithm hash_algo,
    const CertificateView& subject, const CertificateView& issuer)
{
    const boost::optional<Certificate> canonical = subject.canonicalize();
    if (canonical) {
        vanetza::asn1::asn1c_error error;
        const ByteBuffer tbs = vanetza::asn1::encode_oer(
            asn_DEF_Vanetza_Security_ToBeSignedCertificate, &canonical->content()->toBeSigned, error);
        if (!error) {
            return calculate_message_hash(crypto, hash_algo, tbs, issuer);
        }
    }

    return ByteBuffer {};
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
