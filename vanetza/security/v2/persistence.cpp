#include <vanetza/common/serialization.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/v2/persistence.hpp>
#include <boost/variant/get.hpp>
#include <algorithm>
#include <fstream>
#include <stdexcept>

#ifdef VANETZA_WITH_OPENSSL
#include <vanetza/security/backend_openssl.hpp>
#endif

#ifdef VANETZA_WITH_CRYPTOPP
#include <vanetza/security/backend_cryptopp.hpp>
#endif

namespace vanetza
{
namespace security
{
namespace v2
{

ecdsa256::KeyPair load_private_key_from_file(const std::string& key_path)
{
    const PrivateKey private_key = load_private_key_from_der_file(key_path);
    if (private_key.type != KeyType::NistP256) {
        // ETSI TS 103 097 v1.2.1 only defines NIST P-256 keys for v2 security.
        throw std::runtime_error("v2 private key must use the NIST P-256 curve: " + key_path);
    }

#if defined(VANETZA_WITH_OPENSSL)
    const security::PublicKey public_key = openssl::derive_public_key(private_key);
#elif defined(VANETZA_WITH_CRYPTOPP)
    const security::PublicKey public_key = cryptopp::derive_public_key(private_key);
#else
#   warning "no crypto backend available for v2 private key loading"
    const security::PublicKey public_key;
#endif

    ecdsa256::KeyPair key_pair;
    std::copy(private_key.key.begin(), private_key.key.end(), key_pair.private_key.key.begin());
    std::copy(public_key.x.begin(), public_key.x.end(), key_pair.public_key.x.begin());
    std::copy(public_key.y.begin(), public_key.y.end(), key_pair.public_key.y.begin());
    return key_pair;
}

bool save_private_key_pkcs8_der(std::ostream& os, const ecdsa256::KeyPair& key_pair)
{
    // PKCS#8 PrivateKeyInfo wrapping SEC 1 ECPrivateKey for secp256r1
    static const uint8_t header[] = {
        0x30, 0x81, 0x87, /*< SEQUENCE, length 135 */
        0x02, 0x01, 0x00, /*< INTEGER 0 (version) */
        0x30, 0x13, /*< SEQUENCE (AlgorithmIdentifier) */
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, /*< OID 1.2.840.10045.2.1 (ecPublicKey) */
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, /*< OID 1.2.840.10045.3.1.7 (secp256r1) */
        0x04, 0x6d, /*< OCTET STRING, length 109 */
        0x30, 0x6b, /*< SEQUENCE (ECPrivateKey), length 107 */
        0x02, 0x01, 0x01, /*< INTEGER 1 (version) */
        0x04, 0x20, /*< OCTET STRING, length 32 */
    };
    static const uint8_t pub_header[] = {
        0xa1, 0x44, /*< [1] CONSTRUCTED, length 68 */
        0x03, 0x42, /*< BIT STRING, length 66 */
        0x00, /*< 0 unused bits */
        0x04, /*< uncompressed point (x, y) */
    };

    os.write(reinterpret_cast<const char*>(header), sizeof(header));
    os.write(reinterpret_cast<const char*>(key_pair.private_key.key.data()), key_pair.private_key.key.size());
    os.write(reinterpret_cast<const char*>(pub_header), sizeof(pub_header));
    os.write(reinterpret_cast<const char*>(key_pair.public_key.x.data()), key_pair.public_key.x.size());
    os.write(reinterpret_cast<const char*>(key_pair.public_key.y.data()), key_pair.public_key.y.size());
    return os.good();
}

PublicKey load_public_key_from_file(const std::string& key_path)
{
    PublicKey public_key;

    std::ifstream key_src;
    key_src.open(key_path, std::ios::in | std::ios::binary);
    vanetza::InputArchive key_archive(key_src);
    deserialize(key_archive, public_key);

    return public_key;
}

void save_public_key_to_file(const std::string& key_path, const PublicKey& public_key)
{
    std::ofstream dest;
    dest.open(key_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest);
    serialize(archive, public_key);
}

Certificate load_certificate_from_file(const std::string& certificate_path)
{
    Certificate certificate;

    std::ifstream certificate_src;
    certificate_src.open(certificate_path, std::ios::in | std::ios::binary);
    vanetza::InputArchive certificate_archive(certificate_src);
    deserialize(certificate_archive, certificate);

    return certificate;
}

void save_certificate_to_file(const std::string& certificate_path, const Certificate& certificate)
{
    std::ofstream dest;
    dest.open(certificate_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest);
    serialize(archive, certificate);
}

} // namespace v2
} // namespace security
} // namespace vanetza
