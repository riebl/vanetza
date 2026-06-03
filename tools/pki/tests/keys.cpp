#include "openssl.hpp"
#include <gtest/gtest.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

using vanetza::ByteBuffer;
using namespace vanetza::pki;

// Brainpool P-384 known-answer vector.
// y is even, so the compressed form is Y0 and the compressed x bytes equal the uncompressed x bytes.
static const ByteBuffer brainpool_p384_x {{
    0x3b, 0xef, 0x3b, 0xa0, 0x6b, 0x70, 0xe7, 0x20,
    0x03, 0x3e, 0x63, 0xdd, 0x7d, 0xf8, 0x7c, 0xd8,
    0x80, 0x84, 0x25, 0x0a, 0xdc, 0x52, 0xf3, 0xa7,
    0x61, 0xaf, 0xaf, 0xa0, 0x71, 0xdf, 0x29, 0x07,
    0x92, 0x45, 0x90, 0x57, 0x84, 0xe4, 0x85, 0x9d,
    0x02, 0x53, 0x67, 0xd7, 0xf4, 0xe9, 0x46, 0x30
}};

static const ByteBuffer brainpool_p384_y {{
    0x08, 0x82, 0xc2, 0xf5, 0x04, 0x74, 0x72, 0xfe,
    0xcb, 0x65, 0xa4, 0xc4, 0x37, 0xfd, 0x22, 0x08,
    0x59, 0x83, 0x31, 0xbf, 0xb6, 0xcc, 0xb9, 0x30,
    0xb6, 0x73, 0xf7, 0xcc, 0x06, 0x51, 0x1e, 0x14,
    0xba, 0x52, 0x9a, 0xcf, 0x95, 0x25, 0x40, 0x85,
    0x83, 0xe7, 0x72, 0x53, 0x46, 0xb1, 0xb4, 0xba
}};

TEST(KeyCompression, brainpool_p384_compress)
{
    OpenSslPointer<EC_GROUP> group { EC_GROUP_new_by_curve_name(NID_brainpoolP384r1) };
    OpenSslPointer<EC_POINT> point { EC_POINT_new(group.raw()) };
    auto x = make_bignum(brainpool_p384_x);
    auto y = make_bignum(brainpool_p384_y);
    openssl_result(EC_POINT_set_affine_coordinates(group.raw(), point.raw(), x.raw(), y.raw(), nullptr), "set affine");

    OpenSslPointer<EC_KEY> ec_key { EC_KEY_new_by_curve_name(NID_brainpoolP384r1) };
    openssl_result(EC_KEY_set_public_key(ec_key.raw(), point.raw()), "set pubkey");

    PublicKey pub = make_public_key(ec_key.raw());
    EXPECT_EQ(KeyType::BrainpoolP384r1, pub.type);
    EXPECT_EQ(KeyCompression::Y0, pub.compression);
    EXPECT_EQ(brainpool_p384_x, pub.x);
    EXPECT_TRUE(pub.y.empty());
}

TEST(KeyCompression, brainpool_p384_decompress)
{
    PublicKey compressed;
    compressed.type = KeyType::BrainpoolP384r1;
    compressed.compression = KeyCompression::Y0;
    compressed.x = brainpool_p384_x;

    OpenSslPointer<EC_POINT> point = make_ec_point(compressed);
    OpenSslPointer<EC_GROUP> group { EC_GROUP_new_by_curve_name(NID_brainpoolP384r1) };
    OpenSslPointer<BIGNUM> rx { BN_new() };
    OpenSslPointer<BIGNUM> ry { BN_new() };
    openssl_result(EC_POINT_get_affine_coordinates(group.raw(), point.raw(), rx.raw(), ry.raw(), nullptr),
        "get affine");

    EXPECT_EQ(brainpool_p384_x, make_buffer(rx.raw()));
    EXPECT_EQ(brainpool_p384_y, make_buffer(ry.raw()));
}
