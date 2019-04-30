#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/security/ecc_point_decompression_visitor.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <cassert>

namespace vanetza
{
namespace security
{

BackendOpenSsl::BackendOpenSsl()
{
#if OPENSSL_API_COMPAT < 0x10100000L
    ERR_load_crypto_strings();
#else
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#endif
}

EcdsaSignature BackendOpenSsl::sign_data(const ecdsa256::PrivateKey& key, const ByteBuffer& data)
{
    auto priv_key = internal_private_key(key);
    auto digest = calculate_digest(data);

    // sign message data represented by the digest
    openssl::Signature signature { ECDSA_do_sign(digest.data(), digest.size(), priv_key) };
#if OPENSSL_API_COMPAT < 0x10100000L
    const BIGNUM* sig_r = signature->r;
    const BIGNUM* sig_s = signature->s;
#else
    const BIGNUM* sig_r = nullptr;
    const BIGNUM* sig_s = nullptr;
    ECDSA_SIG_get0(signature, &sig_r, &sig_s);
#endif

    EcdsaSignature ecdsa_signature;
    X_Coordinate_Only coordinate;

    if (sig_r && sig_s) {
        const size_t len = field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);

        const auto num_bytes_s = BN_num_bytes(sig_s);
        assert(len >= static_cast<size_t>(num_bytes_s));
        ecdsa_signature.s.resize(len, 0x00);
        BN_bn2bin(sig_s, ecdsa_signature.s.data() + len - num_bytes_s);

        const auto num_bytes_r = BN_num_bytes(sig_r);
        assert(len >= static_cast<size_t>(num_bytes_r));
        coordinate.x.resize(len, 0x00);
        BN_bn2bin(sig_r, coordinate.x.data() + len - num_bytes_r);
    } else {
        throw openssl::Exception();
    }

    ecdsa_signature.R = std::move(coordinate);
    return ecdsa_signature;
}

bool BackendOpenSsl::verify_data(const ecdsa256::PublicKey& key, const ByteBuffer& data, const EcdsaSignature& sig)
{
    auto digest = calculate_digest(data);
    auto pub = internal_public_key(key);
    openssl::Signature signature(sig);

    return (ECDSA_do_verify(digest.data(), digest.size(), signature, pub) == 1);
}

class OpenSslEccPointDecompressionVisitor: public EccPointDecompressionVisitor
{
public:
    virtual Uncompressed decompress(ByteBuffer x, EccPointType type) override {
        // Only with actually compressed points that provide the bit of the y coordinate, we can perform decompression.
        if (type != EccPointType::Compressed_Lsb_Y_0 && type != EccPointType::Compressed_Lsb_Y_1) {
            throw std::logic_error("Unsupported compression type!");
        }

        openssl::BigNumberContext ctx;
        openssl::BigNumber x_coordinate(x);
        const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        EC_POINT *point = EC_POINT_new(group);
        BIGNUM *y_coordinate = BN_new();

        Uncompressed p { x };
        p.y.resize(p.x.size());
#if OPENSSL_API_COMPAT < 0x10101000L
        EC_POINT_set_compressed_coordinates_GFp(group, point, x_coordinate, static_cast<unsigned>(type) % 2, ctx);
        EC_POINT_get_affine_coordinates_GFp(group, point, nullptr, y_coordinate, ctx);
        BN_bn2bin(y_coordinate, p.y.data() + (p.y.size() - BN_num_bytes(y_coordinate)));
#else
        EC_POINT_set_compressed_coordinates(group, point, x_coordinate, static_cast<unsigned>(type) % 2, ctx);
        EC_POINT_get_affine_coordinates(group, point, nullptr, y_coordinate, ctx);
        BN_bn2binpad(y_coordinate, p.y.data(), p.y.size());
#endif
        return p;
    }
};

Uncompressed BackendOpenSsl::decompress_ecc_point(const EccPoint& ecc_point) {
    OpenSslEccPointDecompressionVisitor visitor;
    return boost::apply_visitor(visitor, ecc_point);
}

std::array<uint8_t, 32> BackendOpenSsl::calculate_digest(const ByteBuffer& data) const
{
    static_assert(SHA256_DIGEST_LENGTH == 32, "Unexpected length of SHA256 digest");

    std::array<uint8_t, 32> digest;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(digest.data(), &ctx);
    return digest;
}

openssl::Key BackendOpenSsl::internal_private_key(const ecdsa256::PrivateKey& generic) const
{
    openssl::Key key(NID_X9_62_prime256v1);
    openssl::BigNumber prv(generic.key);
    EC_KEY_set_private_key(key, prv);

    // OpenSSL requires public key, so we recreate it from private key
    openssl::BigNumberContext ctx;
    const EC_GROUP* group = EC_KEY_get0_group(key);
    openssl::Point pub(group);
    openssl::check(EC_POINT_mul(group, pub, prv, nullptr, nullptr, ctx));
    EC_KEY_set_public_key(key, pub);

    openssl::check(EC_KEY_check_key(key));
    return key;
}

openssl::Key BackendOpenSsl::internal_public_key(const ecdsa256::PublicKey& generic) const
{
    openssl::Key key(NID_X9_62_prime256v1);
    openssl::BigNumber x(generic.x);
    openssl::BigNumber y(generic.y);
    EC_KEY_set_public_key_affine_coordinates(key, x, y);

    openssl::check(EC_KEY_check_key(key));
    return key;
}

} // namespace security
} // namespace vanetza
