#include "credential_filesystem_storage.hpp"
#include "openssl.hpp"
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/iterator_range.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <system_error>

namespace vanetza
{
namespace pki
{

CredentialFilesystemStorage::CredentialFilesystemStorage(const std::filesystem::path& root) : m_root(root)
{
    std::filesystem::create_directories(m_root);
}

std::filesystem::path CredentialFilesystemStorage::build_key_path(const PublicKey& key)
{
    auto key_path = m_root / canonical_hexstring(key);
    key_path += ".pem";
    return key_path;
}

void CredentialFilesystemStorage::store(const PublicKey& pub, const PrivateKey& priv)
{
    std::filesystem::path path = build_key_path(pub);
    OpenSslPointer<BIO> out = make_owner_only_bio(path);

    int nid = openssl_nid(priv.type);
    OpenSslPointer<EC_KEY> ec_key { EC_KEY_new_by_curve_name(nid), "construction of EC key failed" };
    OpenSslPointer<BIGNUM> bn_priv { BN_bin2bn(priv.key.data(), priv.key.size(), nullptr),
        "converting private key to BIGNUM failed" };
    openssl_result(EC_KEY_set_private_key(ec_key.raw(), bn_priv.raw()), "setting private key failed");

    OpenSslPointer<EC_POINT> ecp_pub = make_ec_point(pub);
    openssl_result(EC_KEY_set_public_key(ec_key.raw(), ecp_pub.raw()), "setting public key failed");

    openssl_result(EC_KEY_check_key(ec_key.raw()), "EC key is invalid");

    OpenSslPointer<EVP_PKEY> key { EVP_PKEY_new() };
    openssl_result(EVP_PKEY_set1_EC_KEY(key.raw(), ec_key.raw()), "set1_EC_KEY");

    openssl_result(PEM_write_bio_PKCS8PrivateKey(out.raw(), key.raw(), nullptr, nullptr, 0, nullptr, nullptr),
        "writing PEM encoded private key failed");
}

boost::optional<PrivateKey> CredentialFilesystemStorage::fetch(const PublicKey& pub)
{
    std::filesystem::path path = build_key_path(pub);
    if (std::filesystem::is_regular_file(path)) {
        OpenSslPointer<BIO> in { BIO_new_file(path.c_str(), "r"),
            "could not create OpenSSL BIO to read file at " + path.string() };
        OpenSslPointer<EVP_PKEY> key { PEM_read_bio_PrivateKey(in.raw(), nullptr, nullptr, nullptr),
            "reading private key failed" };

        int pub_nid = openssl_nid(pub.type);
        const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(key.raw());
        if (!ec_key) {
            throw std::runtime_error("key is not an EC key");
        }
        const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
        if (!ec_group) {
            throw std::runtime_error("EC group is not set");
        }
        int key_nid = EC_GROUP_get_curve_name(ec_group);
        if (pub_nid != key_nid) {
            throw std::runtime_error("private key has different type than public key");
        }

        PrivateKey priv;
        priv.type = pub.type;
        const BIGNUM* bn_priv = EC_KEY_get0_private_key(ec_key);
        priv.key.resize(BN_num_bytes(bn_priv));
        BN_bn2bin(bn_priv, priv.key.data());
        return priv;
    }

    return boost::none;
}

bool CredentialFilesystemStorage::discard(const PublicKey& key)
{
    std::error_code ec;
    return std::filesystem::remove(build_key_path(key), ec);
}

namespace
{

/**
 * \brief Accept "02"|"03" prefix + 64 hex (P-256) or 96 hex (P-384) chars.
 *
 * Near-misses are rejected here so they are never flagged as orphans and deleted.
 */
bool is_valid_canonical_hex_stem(const std::string& stem)
{
    if (stem.size() != 66 && stem.size() != 98) {
        return false;
    } else if (stem[0] != '0' || (stem[1] != '2' && stem[1] != '3')) {
        return false;
    }
    for (std::size_t i = 2; i < stem.size(); ++i) {
        char c = stem[i];
        const bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
        if (!ok) {
            return false;
        }
    }
    return true;
}

} // namespace

std::filesystem::path CredentialFilesystemStorage::build_key_path(const std::string& canonical_hex) const
{
    auto p = m_root / canonical_hex;
    p += ".pem";
    return p;
}

CredentialNameRange CredentialFilesystemStorage::list() const
{
    auto rng =
        boost::make_iterator_range(std::filesystem::directory_iterator(m_root), std::filesystem::directory_iterator()) |
        boost::adaptors::filtered([](const std::filesystem::directory_entry& e) {
            return e.path().extension() == ".pem" && std::filesystem::is_regular_file(e.path()) &&
                   is_valid_canonical_hex_stem(e.path().stem().string());
        }) |
        boost::adaptors::transformed([](const std::filesystem::directory_entry& e) {
            return e.path().stem().string();
        });
    return CredentialNameRange(rng);
}

bool CredentialFilesystemStorage::discard(const std::string& canonical_hex)
{
    std::error_code ec;
    return std::filesystem::remove(build_key_path(canonical_hex), ec);
}

bool CredentialFilesystemStorage::contains(const std::string& canonical_hex) const
{
    return std::filesystem::is_regular_file(build_key_path(canonical_hex));
}

} // namespace pki
} // namespace vanetza