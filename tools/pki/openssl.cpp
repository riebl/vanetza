#include "openssl.hpp"
#include <vanetza/security/openssl_wrapper.hpp>
#include <cstring>
#include <stdexcept>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace vanetza
{
namespace pki
{

template<> std::function<void(BIGNUM*)> openssl_deleter<BIGNUM>()
{
    return [](BIGNUM* ptr) { BN_clear_free(ptr); };
}

template<> std::function<void(BIO*)> openssl_deleter<BIO>()
{
    return [](BIO* ptr) { BIO_free_all(ptr); };
}

template<> std::function<void(BN_CTX*)> openssl_deleter<BN_CTX>()
{
    return [](BN_CTX* ptr) { BN_CTX_free(ptr); };
}

template<> std::function<void(EC_GROUP*)> openssl_deleter<EC_GROUP>()
{
    return [](EC_GROUP* ptr) { EC_GROUP_clear_free(ptr); };
}

template<> std::function<void(EC_KEY*)> openssl_deleter<EC_KEY>()
{
    return [](EC_KEY* ptr) { EC_KEY_free(ptr); };
}

template<> std::function<void(EC_POINT*)> openssl_deleter<EC_POINT>()
{
    return [](EC_POINT* ptr) { EC_POINT_clear_free(ptr); };
}

template<> std::function<void(ECDSA_SIG*)> openssl_deleter<ECDSA_SIG>()
{
    return [](ECDSA_SIG* ptr) { ECDSA_SIG_free(ptr); };
}

template<> std::function<void(EVP_PKEY*)> openssl_deleter<EVP_PKEY>()
{
    return [](EVP_PKEY* ptr) { EVP_PKEY_free(ptr); };
}

template<> std::function<void(EVP_CIPHER_CTX*)> openssl_deleter<EVP_CIPHER_CTX>()
{
    return [](EVP_CIPHER_CTX* ptr) { EVP_CIPHER_CTX_free(ptr); };
}

int openssl_nid(KeyType key)
{
    int nid = 0;
    switch (key) {
        case KeyType::NistP256:
            nid = NID_X9_62_prime256v1;
            break;
        case KeyType::BrainpoolP256r1:
            nid = NID_brainpoolP256r1;
            break;
        case KeyType::BrainpoolP384r1:
            nid = NID_brainpoolP384r1;
            break;
        default:
            throw std::runtime_error("unknown key type");
            break;
    }
    return nid;
}

KeyType openssl_nid2key(int nid)
{
    switch (nid) {
        case NID_X9_62_prime256v1:
            return KeyType::NistP256;
            break;
        case NID_brainpoolP256r1:
            return KeyType::BrainpoolP256r1;
            break;
        case NID_brainpoolP384r1:
            return KeyType::BrainpoolP384r1;
            break;
        default:
            throw std::runtime_error("unsupported curve type");
            break;
    }
}

KeyType openssl_key_type_from_group_name(const char* name)
{
    if (std::strcmp(name, SN_X9_62_prime256v1) == 0) {
        return KeyType::NistP256;
    } else if (std::strcmp(name, SN_brainpoolP256r1) == 0) {
        return KeyType::BrainpoolP256r1;
    } else if (std::strcmp(name, SN_brainpoolP384r1) == 0) {
        return KeyType::BrainpoolP384r1;
    } else {
        return KeyType::Unspecified;
    }
}

void openssl_result(int rc, const char* msg)
{
    if (rc != 1) {
        throw OpenSslException(ERR_get_error(), msg);
    }
}

OpenSslPointer<BIGNUM> make_bignum(const ByteBuffer& buffer)
{
    OpenSslPointer<BIGNUM> bn { BN_new() };
    if (!BN_bin2bn(buffer.data(), buffer.size(), bn.raw())) {
        throw OpenSslException(ERR_get_error());
    }
    return bn;
}

OpenSslPointer<EC_POINT> make_ec_point(const PublicKey& pub)
{
    int nid = openssl_nid(pub.type);
    OpenSslPointer<EC_GROUP> group { EC_GROUP_new_by_curve_name(nid) };
    OpenSslPointer<EC_POINT> point { EC_POINT_new(group.raw()) };
    OpenSslPointer<BN_CTX> bn_ctx { BN_CTX_new() };

    int rc = 0;
    if (pub.compression == KeyCompression::NoCompression) {
        auto x = make_bignum(pub.x);
        auto y = make_bignum(pub.y);
        rc = EC_POINT_set_affine_coordinates(group.raw(), point.raw(), x.raw(), y.raw(), bn_ctx.raw());
    } else if (pub.compression == KeyCompression::Y0 || pub.compression == KeyCompression::Y1) {
        auto x = make_bignum(pub.x);
        int ybit = pub.compression == KeyCompression::Y1 ? 1 : 0;
        rc = EC_POINT_set_compressed_coordinates(group.raw(), point.raw(), x.raw(), ybit, bn_ctx.raw());
    } else {
        throw std::invalid_argument("invalid key compression type");
    }

    return point;
}

ByteBuffer make_buffer(const BIGNUM* bn)
{
    ByteBuffer buffer;
    buffer.resize(BN_num_bytes(bn));
    BN_bn2bin(bn, buffer.data());
    return buffer;
}

// Variant that emits the BIGNUM as exactly `length` bytes, left-padded with
// zeros. Use this when downstream consumers expect a fixed canonical width
// (e.g. EC field sizes for round-trip-safe key storage).
ByteBuffer make_buffer(const BIGNUM* bn, std::size_t length)
{
    ByteBuffer buffer;
    buffer.resize(length);
    if (BN_bn2binpad(bn, buffer.data(), length) != static_cast<int>(length)) {
        throw OpenSslException(ERR_get_error(), "BN_bn2binpad");
    }
    return buffer;
}

OpenSslPointer<EC_KEY> make_ec_key(const PublicKey& pub)
{
    auto ec_point = make_ec_point(pub);
    OpenSslPointer<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl_nid(pub.type)) };
    openssl_result(EC_KEY_set_public_key(ec_key.raw(), ec_point.raw()), "set public key");
    openssl_result(EC_KEY_check_key(ec_key.raw()), "check key");
    return ec_key;
}

OpenSslPointer<EC_KEY> make_ec_key(const PrivateKey& priv)
{
    // create EC_KEY with private key data
    OpenSslPointer<BIGNUM> bn_priv { BN_bin2bn(priv.key.data(), priv.key.size(), nullptr) };
    OpenSslPointer<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl_nid(priv.type)) };
    openssl_result(EC_KEY_set_private_key(ec_key.raw(), bn_priv.raw()), "setting private key failed");

    // calculate and assign public key
    const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key.raw());
    OpenSslPointer<EC_POINT> ec_point { EC_POINT_new(ec_group) };
    OpenSslPointer<BN_CTX> bn_ctx { BN_CTX_new() };
    openssl_result(EC_POINT_mul(ec_group, ec_point.raw(), bn_priv.raw(), nullptr, nullptr, bn_ctx.raw()),
        "EC point multiplation failed");
    openssl_result(EC_KEY_set_public_key(ec_key.raw(), ec_point.raw()), "setting public key failed");

    // check key integrity
    openssl_result(EC_KEY_check_key(ec_key.raw()), "calculated EC_KEY is invalid");

    return ec_key;
}

PublicKey make_public_key(const EC_KEY* ec_key)
{
    PublicKey pub;
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    pub.type = openssl_nid2key(EC_GROUP_get_curve_name(group));
    const EC_POINT* point = EC_KEY_get0_public_key(ec_key);
    if (point) {
        const std::size_t coord_len = (EC_GROUP_get_degree(group) + 7) / 8;
        OpenSslPointer<BIGNUM> x { BN_new() };
        OpenSslPointer<BIGNUM> y { BN_new() };
        openssl_result(EC_POINT_get_affine_coordinates(group, point, x.raw(), y.raw(), nullptr),
            "get affine coordinates");
        pub.compression = BN_is_bit_set(y.raw(), 0) ? security::KeyCompression::Y1 : security::KeyCompression::Y0;
        pub.x = make_buffer(x.raw(), coord_len);
    } else {
        throw OpenSslException(ERR_get_error(), "EC_KEY_get0_public_key");
    }

    return pub;
}

OpenSslPointer<BIO> make_owner_only_bio(const std::filesystem::path& path)
{
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        throw std::runtime_error("could not create file at " + path.string());
    }
    ::fchmod(fd, S_IRUSR | S_IWUSR); // enforce 0600 even if the file already existed
    BIO* bio = BIO_new_fd(fd, BIO_CLOSE);
    if (!bio) {
        ::close(fd);
        throw OpenSslException(ERR_get_error(), "BIO_new_fd");
    }
    return OpenSslPointer<BIO>(bio);
}

} // namespace pki
} // namespace vanetza
