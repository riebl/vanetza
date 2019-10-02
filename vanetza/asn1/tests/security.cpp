#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/Time64.h>
#include <vanetza/asn1/security/Uint64.h>
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
