#include <vanetza/common/serialization.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/v2/persistence.hpp>
#include <boost/variant/get.hpp>
#include <fstream>

namespace vanetza
{
namespace security
{
namespace v2
{

ecdsa256::KeyPair load_private_key_from_file(const std::string& key_path)
{
    return load_private_key_from_der_file(key_path);
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
