#include <vanetza/common/serialization.hpp>
#include <vanetza/security/v3/persistence.hpp>
#include <boost/variant/get.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <fstream>

namespace vanetza
{
namespace security
{
namespace v3
{

ecdsa256::KeyPair load_private_key_from_file(const std::string& key_path)
{
   CryptoPP::AutoSeededRandomPool rng;

    static std::string HEADER = "-----BEGIN PRIVATE KEY-----";
    static std::string FOOTER = "-----END PRIVATE KEY-----";
    std::ifstream t(key_path);
    std::string RSA_PRIV_KEY((std::istreambuf_iterator<char>(t)),
                 std::istreambuf_iterator<char>());


    size_t pos1, pos2;
    pos1 = RSA_PRIV_KEY.find(HEADER);
    if(pos1 == std::string::npos)
        throw "PEM header not found";

    pos2 = RSA_PRIV_KEY.find(FOOTER, pos1+1);
    if(pos2 == std::string::npos)
        throw "PEM footer not found";

    // Start position and length
    pos1 = pos1 + HEADER.length();
    pos2 = pos2 - pos1;
    std::string keystr = RSA_PRIV_KEY.substr(pos1, pos2);

    // Base64 decode, place in a ByteQueue    
    CryptoPP::ByteQueue queue;
    CryptoPP::Base64Decoder decoder;

    decoder.Attach(new CryptoPP::Redirector(queue));
    decoder.Put(reinterpret_cast<const uint8_t*>(keystr.data()), keystr.length());
    decoder.MessageEnd();

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey private_key;
    private_key.Load(queue);

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

v2::PublicKey load_public_key_from_file(const std::string& key_path)
{
    v2::PublicKey public_key;

    std::ifstream key_src;
    key_src.open(key_path, std::ios::in | std::ios::binary);
    vanetza::InputArchive key_archive(key_src);
    v2::deserialize(key_archive, public_key);

    return public_key;
}

void save_public_key_to_file(const std::string& key_path, const v2::PublicKey& public_key)
{
    std::ofstream dest;
    dest.open(key_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest);
    v2::serialize(archive, public_key);
}

Certificate load_certificate_from_file(const std::string& certificate_path)
{
    Certificate certificate;

    std::ifstream certificate_src;
    certificate_src.open(certificate_path, std::ios::in | std::ios::binary);
    vanetza::ByteBuffer buffer(std::istreambuf_iterator<char>(certificate_src), {});
    certificate.decode(buffer);

    return certificate;
}

void save_certificate_to_file(const std::string& certificate_path, Certificate& certificate)
{
    std::ofstream dest;
    dest.open(certificate_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest);
    serialize(archive, certificate);
}

} // namespace v3
} // namespace security
} // namespace vanetza
