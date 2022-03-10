#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/Time64.h>
#include <vanetza/asn1/security/Uint64.h>
#include <algorithm>
#include <cstdint>
#include <limits>

using namespace vanetza::asn1;

TEST(SecurityAsn1, Time64)
{
    asn1c_wrapper<Time64_t> time { asn_DEF_Time64 };
    EXPECT_EQ(0, asn_umax2INTEGER(&*time, std::numeric_limits<std::uint64_t>::max()));

    std::uint64_t tmp = 0;
    asn_INTEGER2umax(&*time, &tmp);
    EXPECT_EQ(tmp, std::numeric_limits<std::uint64_t>::max());

    time.encode();
    EXPECT_EQ(8, time.size());
}

TEST(SecuriyAsn1, Uint64)
{
    asn1c_wrapper<Uint64_t> uint { asn_DEF_Uint64 };
    EXPECT_EQ(0, asn_umax2INTEGER(&*uint, std::numeric_limits<std::uint64_t>::max()));

    std::uint64_t tmp = 0;
    asn_INTEGER2umax(&*uint, &tmp);
    EXPECT_EQ(tmp, std::numeric_limits<std::uint64_t>::max());

    uint.encode();
    EXPECT_EQ(8, uint.size());
}

TEST(SecurityAsn1, Uint64_roundtrip_max_value)
{
    asn1c_wrapper<Uint64_t> tx { asn_DEF_Uint64 };
    EXPECT_EQ(0, asn_umax2INTEGER(&*tx, std::numeric_limits<std::uint64_t>::max()));
    const vanetza::ByteBuffer buffer = tx.encode();
    EXPECT_EQ(8, buffer.size());
    EXPECT_TRUE(std::all_of(buffer.begin(), buffer.end(),
                [](std::uint8_t c) { return c == 0xff; }));

    asn1c_wrapper<Uint64_t> rx { asn_DEF_Uint64 };
    EXPECT_TRUE(rx.decode(buffer));
    std::uint64_t value = 0;
    EXPECT_EQ(0, asn_INTEGER2umax(&*rx, &value));
    EXPECT_EQ(value, std::numeric_limits<std::uint64_t>::max());
}
