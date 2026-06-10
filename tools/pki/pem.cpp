#include "pem.hpp"
#include "openssl.hpp"
#include <openssl/core_names.h>
#include <openssl/pem.h>

namespace vanetza
{
namespace pki
{

namespace
{

boost::optional<PrivateKey> parse_pem_private_key(const void* data, std::size_t size)
{
    OpenSslPointer<BIO> bio { BIO_new(BIO_s_mem()) };
    int rc = BIO_write(bio.raw(), data, size);
    if (rc < 0) {
        throw security::openssl::Exception();
    }

    EVP_PKEY* evp_key_raw = PEM_read_bio_PrivateKey(bio.raw(), nullptr, nullptr, nullptr);
    if (evp_key_raw == nullptr) {
        return boost::none;
    } else if (EVP_PKEY_get_base_id(evp_key_raw) != EVP_PKEY_EC) {
        return boost::none;
    }
    OpenSslPointer<EVP_PKEY> evp_key { evp_key_raw }; /*< safe deallocation*/

    BIGNUM* bn_priv_raw = nullptr;
    EVP_PKEY_get_bn_param(evp_key.raw(), OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv_raw);
    OpenSslPointer<BIGNUM> bn_priv { bn_priv_raw }; /*< safe deallocation */

    char group[80];
    if (!EVP_PKEY_get_group_name(evp_key.raw(), group, sizeof(group), nullptr)) {
        return boost::none;
    }

    PrivateKey priv_key;
    priv_key.type = openssl_key_type_from_group_name(group);
    priv_key.key.resize(BN_num_bytes(bn_priv_raw));
    BN_bn2bin(bn_priv_raw, priv_key.key.data());

    return priv_key;
}

} // namespace

boost::optional<PrivateKey> parse_pem_private_key(const std::string& pem)
{
    return parse_pem_private_key(pem.data(), pem.size());
}

boost::optional<PrivateKey> parse_pem_private_key(const ByteBuffer& pem)
{
    return parse_pem_private_key(pem.data(), pem.size());
}

std::string make_pem(const PrivateKey& priv)
{
    OpenSslPointer<EC_KEY> ec_key = make_ec_key(priv);
    OpenSslPointer<EVP_PKEY> evp_key { EVP_PKEY_new() };
    openssl_result(EVP_PKEY_set1_EC_KEY(evp_key.raw(), ec_key.raw()), "EVP_PKEY_set1_EC_KEY");

    // unencrypted PKCS#8 PrivateKeyInfo, read back by parse_pem_private_key
    OpenSslPointer<BIO> bio { BIO_new(BIO_s_mem()) };
    openssl_result(PEM_write_bio_PrivateKey(bio.raw(), evp_key.raw(), nullptr, nullptr, 0, nullptr, nullptr),
        "PEM_write_bio_PrivateKey");

    char* data = nullptr;
    long len = BIO_get_mem_data(bio.raw(), &data);
    return std::string(data, len);
}

void write_pem_private_key(const PrivateKey& priv, const std::filesystem::path& path)
{
    std::string pem = make_pem(priv);
    auto bio = make_owner_only_bio(path);
    if (BIO_write(bio.raw(), pem.data(), pem.size()) != static_cast<int>(pem.size())) {
        throw OpenSslException(ERR_get_error(), "writing PEM to key file failed");
    }
}

} // namespace pki
} // namespace vanetza
