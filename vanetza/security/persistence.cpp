#include "persistence.hpp"
#include <boost/variant/get.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <fstream>

namespace vanetza
{
namespace security
{

ecdsa256::KeyPair load_private_key_from_file(const std::string& key_path)
{
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey private_key;
    CryptoPP::FileSource key_file(key_path.c_str(), true);
    private_key.Load(key_file);

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

ecdsa256::PublicKey load_public_key_from_file(const std::string& key_path)
{
    EccPoint ecc_point;

    std::ifstream key_src;
    key_src.open(key_path, std::ios::in | std::ios::binary);
    vanetza::InputArchive key_archive(key_src, boost::archive::no_header);
    deserialize(key_archive, ecc_point, PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256);

    auto coordinates = boost::get<Uncompressed>(ecc_point);

    ecdsa256::PublicKey pub;
    if (coordinates.x.size() != pub.x.size() || coordinates.y.size() != pub.y.size()) {
        throw std::runtime_error("Coordinate size mismatch");
    }

    std::copy_n(coordinates.x.begin(), pub.x.size(), pub.x.data());
    std::copy_n(coordinates.y.begin(), pub.y.size(), pub.y.data());

    return pub;
}

void save_public_key_to_file(const std::string& key_path, const ecdsa256::PublicKey& public_key)
{
    Uncompressed coordinates;
    coordinates.x.assign(public_key.x.begin(), public_key.x.end());
    coordinates.y.assign(public_key.y.begin(), public_key.y.end());
    EccPoint ecc_point = coordinates;

    std::ofstream dest;
    dest.open(key_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest, boost::archive::no_header);
    serialize(archive, ecc_point, PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256);
}

Certificate load_certificate_from_file(const std::string& certificate_path)
{
    Certificate certificate;

    std::ifstream certificate_src;
    certificate_src.open(certificate_path, std::ios::in | std::ios::binary);
    vanetza::InputArchive certificate_archive(certificate_src, boost::archive::no_header);
    deserialize(certificate_archive, certificate);

    return certificate;
}

void save_certificate_to_file(const std::string& certificate_path, const Certificate& certificate)
{
    std::ofstream dest;
    dest.open(certificate_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest, boost::archive::no_header);
    serialize(archive, certificate);
}

} // namespace security
} // namespace vanetza
