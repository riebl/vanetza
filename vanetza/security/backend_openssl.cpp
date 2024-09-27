#include <vanetza/security/backend_openssl.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/v2/public_key.hpp>
#include <vanetza/security/v2/signature.hpp>
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

namespace
{

int openssl_nid(KeyType key)
{
    int nid;
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
            nid = NID_undef;
            break;
    }
    return nid;
}

} // namespace

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
    auto digest = calculate_sha256_digest(data);

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
        const size_t len = field_size(v2::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);

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

Signature BackendOpenSsl::sign_data(const PrivateKey& key, const ByteBuffer& data)
{
    auto priv_key = internal_private_key(key);
    auto digest = calculate_hash(key.type, data);

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

    Signature ecdsa_signature;
    ecdsa_signature.type = key.type;

    if (sig_r && sig_s) {
        const size_t len = key_length(key.type);

        const auto num_bytes_s = BN_num_bytes(sig_s);
        assert(len >= static_cast<size_t>(num_bytes_s));
        ecdsa_signature.s.resize(len, 0x00);
        BN_bn2bin(sig_s, ecdsa_signature.s.data() + len - num_bytes_s);

        const auto num_bytes_r = BN_num_bytes(sig_r);
        assert(len >= static_cast<size_t>(num_bytes_r));
        ecdsa_signature.r.resize(len, 0x00);
        BN_bn2bin(sig_r, ecdsa_signature.r.data() + len - num_bytes_r);
    } else {
        throw openssl::Exception();
    }

    return ecdsa_signature;
}

bool BackendOpenSsl::verify_data(const ecdsa256::PublicKey& key, const ByteBuffer& data, const EcdsaSignature& sig)
{
    auto digest = calculate_sha256_digest(data);
    auto pub = internal_public_key(key);
    openssl::Signature signature(sig);

    return (ECDSA_do_verify(digest.data(), digest.size(), signature, pub) == 1);
}

bool BackendOpenSsl::verify_digest(const PublicKey& gpub, const ByteBuffer& digest, const Signature& gsig)
{
    if (gpub.type != gsig.type) {
        return false;
    }

    openssl::Key pub = internal_public_key(gpub);
    openssl::Signature sig { gsig };
    return ECDSA_do_verify(digest.data(), digest.size(), sig, pub) == 1;
}

boost::optional<Uncompressed> BackendOpenSsl::decompress_point(const EccPoint& ecc_point)
{
    struct DecompressionVisitor : public boost::static_visitor<bool>
    {
        bool operator()(const X_Coordinate_Only&)
        {
            return false;
        }

        bool operator()(const Compressed_Lsb_Y_0& p)
        {
            return decompress(p.x, 0);
        }

        bool operator()(const Compressed_Lsb_Y_1& p)
        {
            return decompress(p.x, 1);
        }

        bool operator()(const Uncompressed& p)
        {
            result = p;
            return true;
        }

        bool decompress(const ByteBuffer& x, int y_bit)
        {
            openssl::BigNumberContext ctx;
            openssl::BigNumber x_coordinate(x);
            openssl::Group group(NID_X9_62_prime256v1);
            openssl::Point point(group);
            openssl::BigNumber y_coordinate;

            result.x = x;
            result.y.resize(result.x.size());

#if OPENSSL_API_COMPAT < 0x10101000L
            EC_POINT_set_compressed_coordinates_GFp(group, point, x_coordinate, y_bit, ctx);
            EC_POINT_get_affine_coordinates_GFp(group, point, nullptr, y_coordinate, ctx);
            std::size_t y_coordinate_bytes = BN_num_bytes(y_coordinate);
            if (y_coordinate_bytes <= result.y.size()) {
                BN_bn2bin(y_coordinate, result.y.data() + (result.y.size() - y_coordinate_bytes));
                return true;
            } else {
                return false;
            }
#else
            EC_POINT_set_compressed_coordinates(group, point, x_coordinate, y_bit, ctx);
            EC_POINT_get_affine_coordinates(group, point, nullptr, y_coordinate, ctx);
            return (BN_bn2binpad(y_coordinate, result.y.data(), result.y.size()) != -1);
#endif
        }

        Uncompressed result;
    };

    DecompressionVisitor visitor;
    if (boost::apply_visitor(visitor, ecc_point)) {
        return visitor.result;
    } else {
        return boost::none;
    }
}

ByteBuffer BackendOpenSsl::calculate_hash(KeyType key, const ByteBuffer& data)
{
    ByteBuffer result;
    switch (key)
    {
        case KeyType::NistP256:
        case KeyType::BrainpoolP256r1: {
            auto digest = calculate_sha256_digest(data);
            result.assign(digest.begin(), digest.end());
            break;
        }
        case KeyType::BrainpoolP384r1: {
            auto digest = calculate_sha384_digest(data);
            result.assign(digest.begin(), digest.end());
            break;
        }
        default:
            break;
    }
    return result;
}

std::array<uint8_t, 32> BackendOpenSsl::calculate_sha256_digest(const ByteBuffer& data) const
{
    static_assert(SHA256_DIGEST_LENGTH == 32, "Unexpected length of SHA256 digest");

    std::array<uint8_t, 32> digest;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(digest.data(), &ctx);
    return digest;
}

std::array<uint8_t, 48> BackendOpenSsl::calculate_sha384_digest(const ByteBuffer& data) const
{
    static_assert(SHA384_DIGEST_LENGTH == 48, "Unexpected length of SHA384 digest");

    std::array<uint8_t, 48> digest;
    SHA384(data.data(), data.size(), digest.data());
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

openssl::Key BackendOpenSsl::internal_private_key(const PrivateKey& generic) const
{
    openssl::Key key(openssl_nid(generic.type));
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

openssl::Key BackendOpenSsl::internal_public_key(const PublicKey& generic) const
{
    openssl::Key key(openssl_nid(generic.type));
    openssl::Point point = internal_ec_point(generic);
    EC_KEY_set_public_key(key, point);

    openssl::check(EC_KEY_check_key(key));
    return key;
}

openssl::Point BackendOpenSsl::internal_ec_point(const PublicKey& generic) const
{
    openssl::Group group { openssl_nid(generic.type) };
    openssl::Point point { group };
    openssl::BigNumberContext bn_ctx;

    switch (generic.compression)
    {
        case KeyCompression::NoCompression:
            EC_POINT_set_affine_coordinates(group, point,
                openssl::BigNumber { generic.x }, openssl::BigNumber {generic.y },
                bn_ctx);
            break;
        case KeyCompression::Y0:
            EC_POINT_set_compressed_coordinates(group, point, openssl::BigNumber { generic.x }, 0, bn_ctx);
            break;
        case KeyCompression::Y1:
            EC_POINT_set_compressed_coordinates(group, point, openssl::BigNumber { generic.x }, 1, bn_ctx);
            break;
        default:
            // no-op
            break;
    }

    return point;
}

} // namespace security
} // namespace vanetza
