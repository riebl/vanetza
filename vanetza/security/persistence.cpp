#include <vanetza/security/persistence.hpp>
#include <vanetza/security/key_type.hpp>
#include <fstream>
#include <stdexcept>

#ifdef VANETZA_WITH_OPENSSL
#include <vanetza/security/openssl_wrapper.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#endif

#ifdef VANETZA_WITH_CRYPTOPP
#include <cryptopp/base64.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/integer.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/sha.h>
#endif

namespace vanetza
{
namespace security
{

#ifdef VANETZA_WITH_OPENSSL
namespace
{

KeyType key_type_from_nid(int nid)
{
    switch (nid) {
        case NID_X9_62_prime256v1:
            return KeyType::NistP256;
        case NID_brainpoolP256r1:
            return KeyType::BrainpoolP256r1;
        case NID_brainpoolP384r1:
            return KeyType::BrainpoolP384r1;
        default:
            return KeyType::Unspecified;
    }
}

PrivateKey extract_private_key(openssl::EvpKey& pkey)
{
    openssl::Key ec_key(EVP_PKEY_get1_EC_KEY(pkey));
    if (!ec_key) {
        throw std::runtime_error("Key is not an EC key");
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    const KeyType type = key_type_from_nid(group ? EC_GROUP_get_curve_name(group) : NID_undef);
    if (type == KeyType::Unspecified) {
        throw std::runtime_error("Unsupported EC curve in private key");
    }

    const BIGNUM* priv_bn = EC_KEY_get0_private_key(ec_key);
    if (!priv_bn) {
        throw std::runtime_error("EC key has no private component");
    }

    PrivateKey key;
    key.type = type;
    key.key.resize(key_length(type));
    if (BN_bn2binpad(priv_bn, key.key.data(), key.key.size()) < 0) {
        throw std::runtime_error("private key does not fit the curve length");
    }
    return key;
}

} // namespace

PrivateKey load_private_key_from_pem_file_openssl(const std::string& key_path)
{
    openssl::Bio bio(BIO_new_file(key_path.c_str(), "rb"));
    if (!bio) {
        throw std::runtime_error("Cannot open key file: " + key_path);
    }
    openssl::EvpKey pkey(PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr));
    if (!pkey) {
        throw std::runtime_error("Failed to load PEM private key from: " + key_path);
    }
    return extract_private_key(pkey);
}

PrivateKey load_private_key_from_der_file_openssl(const std::string& key_path)
{
    openssl::Bio bio(BIO_new_file(key_path.c_str(), "rb"));
    if (!bio) {
        throw std::runtime_error("Cannot open key file: " + key_path);
    }
    openssl::EvpKey pkey(d2i_PrivateKey_bio(bio, nullptr));
    if (!pkey) {
        throw std::runtime_error("Failed to load DER private key from: " + key_path);
    }
    return extract_private_key(pkey);
}
#endif /* VANETZA_WITH_OPENSSL */

#ifdef VANETZA_WITH_CRYPTOPP
namespace
{

using EcPrivateKey = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey;
using EcGroupParameters = CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>;

KeyType detect_curve(const EcGroupParameters& gp)
{
    KeyType key_type = KeyType::Unspecified;

    if (EcGroupParameters(CryptoPP::ASN1::secp256r1()) == gp) {
        key_type = KeyType::NistP256;
    } else if (EcGroupParameters(CryptoPP::ASN1::brainpoolP256r1()) == gp) {
        key_type = KeyType::BrainpoolP256r1;
    } else if (EcGroupParameters(CryptoPP::ASN1::brainpoolP384r1()) == gp) {
        key_type = KeyType::BrainpoolP384r1;
    }

    return key_type;
}

PrivateKey extract_private_key(CryptoPP::BufferedTransformation& der)
{
    CryptoPP::AutoSeededRandomPool rng;
    EcPrivateKey private_key;
    private_key.Load(der);
    if (!private_key.Validate(rng, 3)) {
        throw std::runtime_error("Private key validation failed");
    }

    const KeyType type = detect_curve(private_key.GetGroupParameters());
    if (type == KeyType::Unspecified) {
        throw std::runtime_error("Unsupported EC curve in private key");
    }

    PrivateKey key;
    key.type = type;
    key.key.resize(key_length(type));
    private_key.GetPrivateExponent().Encode(key.key.data(), key.key.size());
    return key;
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

} // namespace

PrivateKey load_private_key_from_pem_file_cryptopp(const std::string& key_path)
{
    std::ifstream file(key_path);
    if (!file) {
        throw std::runtime_error("Cannot open key file: " + key_path);
    }
    CryptoPP::ByteQueue der;
    pem_decode(file, der);
    return extract_private_key(der);
}

PrivateKey load_private_key_from_der_file_cryptopp(const std::string& key_path)
{
    try {
        CryptoPP::FileSource source(key_path.c_str(), true);
        return extract_private_key(source);
    } catch (const CryptoPP::FileStore::OpenErr&) {
        throw std::runtime_error("Cannot open key file: " + key_path);
    }
}
#endif /* VANETZA_WITH_CRYPTOPP */

PrivateKey load_private_key_from_pem_file(const std::string& key_path)
{
#if defined(VANETZA_WITH_OPENSSL)
    return load_private_key_from_pem_file_openssl(key_path);
#elif defined(VANETZA_WITH_CRYPTOPP)
    return load_private_key_from_pem_file_cryptopp(key_path);
#else
#   warning "no crypto backend available for persistence"
    return PrivateKey {};
#endif
}

PrivateKey load_private_key_from_der_file(const std::string& key_path)
{
#if defined(VANETZA_WITH_OPENSSL)
    return load_private_key_from_der_file_openssl(key_path);
#elif defined(VANETZA_WITH_CRYPTOPP)
    return load_private_key_from_der_file_cryptopp(key_path);
#else
#   warning "no crypto backend available for persistence"
    return PrivateKey {};
#endif
}

} // namespace security
} // namespace vanetza
