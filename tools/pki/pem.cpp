#include "pem.hpp"
#include "openssl.hpp"
#include <openssl/core_names.h>
#include <openssl/pem.h>

namespace vanetza
{
namespace pki
{

boost::optional<PrivateKey> read_pem_private_key(const std::string& pem)
{
    OpenSslPointer<BIO> bio { BIO_new(BIO_s_mem()) };
    int rc = BIO_write(bio.raw(), pem.data(), pem.size());
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

} // namespace pki
} // namespace vanetza
