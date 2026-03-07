#include <vanetza/common/serialization.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/v3/persistence.hpp>
#include <boost/variant/get.hpp>
#include <fstream>

namespace vanetza
{
namespace security
{
namespace v3
{

ecdsa256::KeyPair load_private_key_from_file(const std::string& key_path)
{
    return load_private_key_from_pem_file(key_path);
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

void save_certificate_to_file(const std::string& certificate_path, const Certificate& certificate)
{
    std::ofstream dest;
    dest.open(certificate_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest);
    serialize(archive, certificate);
}

} // namespace v3
} // namespace security
} // namespace vanetza
