#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/hmac.hpp>
#include <gtest/gtest.h>

using namespace vanetza::security;
using vanetza::ByteBuffer;

class HmacTest : public ::testing::Test
{
protected:
    ByteBuffer data = {0x01, 0x02, 0x03, 0x04, 0x05};
    HmacKey key = {{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    }};
};

#if defined VANETZA_WITH_OPENSSL || defined VANETZA_WITH_CRYPTOPP
TEST_F(HmacTest, create_hmac_tag)
{
    KeyTag tag = create_hmac_tag(data, key);
    KeyTag zero = {};
    EXPECT_NE(tag, zero);
}

TEST_F(HmacTest, deterministic)
{
    KeyTag tag1 = create_hmac_tag(data, key);
    KeyTag tag2 = create_hmac_tag(data, key);
    EXPECT_EQ(tag1, tag2);
}

TEST_F(HmacTest, different_data_different_tag)
{
    ByteBuffer other_data = {0x05, 0x04, 0x03, 0x02, 0x01};
    KeyTag tag1 = create_hmac_tag(data, key);
    KeyTag tag2 = create_hmac_tag(other_data, key);
    EXPECT_NE(tag1, tag2);
}

TEST_F(HmacTest, different_key_different_tag)
{
    HmacKey other_key = {};
    KeyTag tag1 = create_hmac_tag(data, key);
    KeyTag tag2 = create_hmac_tag(data, other_key);
    EXPECT_NE(tag1, tag2);
}
#endif

#if defined VANETZA_WITH_OPENSSL
TEST_F(HmacTest, openssl)
{
    KeyTag tag = create_hmac_tag_openssl(data, key);
    KeyTag zero = {};
    EXPECT_NE(tag, zero);
}
#endif

#if defined VANETZA_WITH_CRYPTOPP
TEST_F(HmacTest, cryptopp)
{
    KeyTag tag = create_hmac_tag_cryptopp(data, key);
    KeyTag zero = {};
    EXPECT_NE(tag, zero);
}
#endif

#if defined VANETZA_WITH_OPENSSL && defined VANETZA_WITH_CRYPTOPP
TEST_F(HmacTest, openssl_and_cryptopp_match)
{
    KeyTag tag_openssl = create_hmac_tag_openssl(data, key);
    KeyTag tag_cryptopp = create_hmac_tag_cryptopp(data, key);
    EXPECT_EQ(tag_openssl, tag_cryptopp);
}
#endif
