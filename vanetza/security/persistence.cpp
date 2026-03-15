#include <vanetza/security/persistence.hpp>
#include <fstream>
#include <stdexcept>

#ifdef VANETZA_WITH_OPENSSL
#include <vanetza/security/openssl_wrapper.hpp>
#include <openssl/ec.h>
#include <openssl/pem.h>
#endif

#ifdef VANETZA_WITH_CRYPTOPP
#include <cryptopp/base64.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#endif

namespace vanetza
{
namespace security
{

#ifdef VANETZA_WITH_OPENSSL
namespace
{

ecdsa256::KeyPair extract_key_pair(openssl::EvpKey& pkey)
{
    openssl::Key ec_key(EVP_PKEY_get1_EC_KEY(pkey));
    if (!ec_key) {
        throw std::runtime_error("Key is not an EC key");
    }

    const BIGNUM* priv_bn = EC_KEY_get0_private_key(ec_key);
    const EC_POINT* pub_point = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);

    ecdsa256::KeyPair key_pair;
    key_pair.private_key.key.fill(0);
    int priv_bytes = BN_num_bytes(priv_bn);
    BN_bn2bin(priv_bn, key_pair.private_key.key.data() + key_pair.private_key.key.size() - priv_bytes);

    openssl::BigNumber x;
    openssl::BigNumber y;
    openssl::BigNumberContext ctx;
    EC_POINT_get_affine_coordinates(group, pub_point, x, y, ctx);
    BN_bn2binpad(x, key_pair.public_key.x.data(), key_pair.public_key.x.size());
    BN_bn2binpad(y, key_pair.public_key.y.data(), key_pair.public_key.y.size());

    return key_pair;
}

} // anonymous namespace

ecdsa256::KeyPair load_private_key_from_pem_file_openssl(const std::string& key_path)
{
    openssl::Bio bio(BIO_new_file(key_path.c_str(), "rb"));
    if (!bio) {
        throw std::runtime_error("Cannot open key file: " + key_path);
    }

    openssl::EvpKey pkey(PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr));
    if (!pkey) {
        throw std::runtime_error("Failed to load PEM private key from: " + key_path);
    }

    return extract_key_pair(pkey);
}

ecdsa256::KeyPair load_private_key_from_der_file_openssl(const std::string& key_path)
{
    openssl::Bio bio(BIO_new_file(key_path.c_str(), "rb"));
    if (!bio) {
        throw std::runtime_error("Cannot open key file: " + key_path);
    }

    openssl::EvpKey pkey(d2i_PrivateKey_bio(bio, nullptr));
    if (!pkey) {
        throw std::runtime_error("Failed to load DER private key from: " + key_path);
    }

    return extract_key_pair(pkey);
}
#endif /* VANETZA_WITH_OPENSSL */

#ifdef VANETZA_WITH_CRYPTOPP
namespace
{

ecdsa256::KeyPair load_and_validate_der(CryptoPP::BufferedTransformation& source)
{
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey private_key;
    private_key.Load(source);

    if (!private_key.Validate(rng, 3)) {
        throw std::runtime_error("Private key validation failed");
    }

    ecdsa256::KeyPair key_pair;

    auto& private_exponent = private_key.GetPrivateExponent();
    private_exponent.Encode(key_pair.private_key.key.data(), key_pair.private_key.key.size());

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey public_key;
    private_key.MakePublicKey(public_key);

    auto& public_element = public_key.GetPublicElement();
    public_element.x.Encode(key_pair.public_key.x.data(), key_pair.public_key.x.size());
    public_element.y.Encode(key_pair.public_key.y.data(), key_pair.public_key.y.size());

    return key_pair;
}

void pem_decode(std::istream& in, CryptoPP::BufferedTransformation& dest)
{
    static const std::string HEADER = "-----BEGIN PRIVATE KEY-----";
    static const std::string FOOTER = "-----END PRIVATE KEY-----";

    std::string line;
    while (std::getline(in, line)) {
        if (line.find(HEADER) != std::string::npos) {
            break;
        }
    }
    if (!in) {
        throw std::runtime_error("PEM header not found");
    }

    CryptoPP::Base64Decoder decoder;
    decoder.Attach(new CryptoPP::Redirector(dest));

    while (std::getline(in, line)) {
        if (line.find(FOOTER) != std::string::npos) {
            break;
        }
        decoder.Put(reinterpret_cast<const uint8_t*>(line.data()), line.length());
    }
    if (!in) {
        throw std::runtime_error("PEM footer not found");
    }

    decoder.MessageEnd();
}

} // anonymous namespace

ecdsa256::KeyPair load_private_key_from_pem_file_cryptopp(const std::string& key_path)
{
    std::ifstream file(key_path);
    CryptoPP::ByteQueue der;
    pem_decode(file, der);
    return load_and_validate_der(der);
}

ecdsa256::KeyPair load_private_key_from_der_file_cryptopp(const std::string& key_path)
{
    try {
        CryptoPP::FileSource source(key_path.c_str(), true);
        return load_and_validate_der(source);
    } catch (const CryptoPP::FileStore::OpenErr&) {
        throw std::runtime_error("Cannot open key file: " + key_path);
    }
}
#endif /* VANETZA_WITH_CRYPTOPP */

ecdsa256::KeyPair load_private_key_from_pem_file(const std::string& key_path)
{
#if defined(VANETZA_WITH_OPENSSL)
    return load_private_key_from_pem_file_openssl(key_path);
#elif defined(VANETZA_WITH_CRYPTOPP)
    return load_private_key_from_pem_file_cryptopp(key_path);
#else
#   warning "no crypto backend available for persistence"
    return ecdsa256::KeyPair {};
#endif
}

ecdsa256::KeyPair load_private_key_from_der_file(const std::string& key_path)
{
#if defined(VANETZA_WITH_OPENSSL)
    return load_private_key_from_der_file_openssl(key_path);
#elif defined(VANETZA_WITH_CRYPTOPP)
    return load_private_key_from_der_file_cryptopp(key_path);
#else
#   warning "no crypto backend available for persistence"
    return ecdsa256::KeyPair {};
#endif
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

} // namespace security
} // namespace vanetza
