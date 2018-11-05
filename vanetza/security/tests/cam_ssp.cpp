#include <vanetza/security/cam_ssp.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <set>

using vanetza::ByteBuffer;
using namespace vanetza::security;

static const std::set<CamPermission> all {{
    CamPermission::CEN_DSRC_Tolling_Zone,
    CamPermission::Public_Transport,
    CamPermission::Special_Transport,
    CamPermission::Dangerous_Goods,
    CamPermission::Roadwork,
    CamPermission::Rescue,
    CamPermission::Emergency,
    CamPermission::Safety_Car,
    CamPermission::Closed_Lanes,
    CamPermission::Request_For_Right_Of_Way,
    CamPermission::Request_For_Free_Crossing_At_Traffic_Light,
    CamPermission::No_Passing,
    CamPermission::No_Passing_For_Trucks,
    CamPermission::Speed_Limit,
}};

TEST(CamSsp, empty)
{
    CamPermissions empty;
    EXPECT_TRUE(std::none_of(all.begin(), all.end(), [empty](CamPermission cp) { return empty.has(cp); }));
    EXPECT_TRUE(empty.none());
}

TEST(CamSsp, single)
{
    CamPermissions single(CamPermission::Safety_Car);
    EXPECT_FALSE(single.none());
    EXPECT_TRUE(single.has(CamPermission::Safety_Car));

    std::set<CamPermission> rest = all;
    rest.erase(CamPermission::Safety_Car);
    EXPECT_TRUE(std::none_of(rest.begin(), rest.end(), [single](CamPermission cp) { return single.has(cp); }));
}

TEST(CamSsp, multiple)
{
    CamPermissions multiple({CamPermission::Roadwork, CamPermission::Public_Transport, CamPermission::Speed_Limit});
    EXPECT_TRUE(multiple.has(CamPermission::Roadwork));
    EXPECT_TRUE(multiple.has(CamPermission::Public_Transport));
    EXPECT_TRUE(multiple.has(CamPermission::Speed_Limit));
    EXPECT_TRUE(multiple.has({CamPermission::Roadwork, CamPermission::Public_Transport, CamPermission::Speed_Limit}));
}

TEST(CamSsp, manipulation)
{
    CamPermissions ssp({CamPermission::No_Passing, CamPermission::Rescue});
    EXPECT_TRUE(ssp.has({CamPermission::Rescue, CamPermission::No_Passing}));
    ssp.remove(CamPermission::Rescue);
    EXPECT_FALSE(ssp.has({CamPermission::Rescue, CamPermission::No_Passing}));
    EXPECT_TRUE(ssp.has(CamPermission::No_Passing));

    ssp.remove(CamPermission::Speed_Limit);
    EXPECT_FALSE(ssp.has(CamPermission::Speed_Limit));
    EXPECT_TRUE(ssp.has(CamPermission::No_Passing));

    ssp.add(CamPermission::Closed_Lanes);
    EXPECT_TRUE(ssp.has({CamPermission::Closed_Lanes, CamPermission::No_Passing}));
    ssp.remove(CamPermission::No_Passing).remove(CamPermission::Closed_Lanes);
    EXPECT_TRUE(ssp.none());
}

TEST(CamSsp, serialization)
{
    CamPermissions ssp;
    const auto empty_ssp_buffer = ssp.encode();
    EXPECT_EQ(ByteBuffer({0x01, 0x00, 0x00}), empty_ssp_buffer);

    ssp.add(CamPermission::CEN_DSRC_Tolling_Zone);
    const auto dsrc_ssp_buffer = ssp.encode();
    EXPECT_EQ(ByteBuffer({0x01, 0x80, 0x00}), dsrc_ssp_buffer);

    ssp.add(CamPermission::Speed_Limit);
    const auto extremes_ssp_buffer = ssp.encode();
    EXPECT_EQ(ByteBuffer({0x01, 0x80, 0x04}), extremes_ssp_buffer);

    CamPermissions decoded = CamPermissions::decode(extremes_ssp_buffer);
    EXPECT_EQ(extremes_ssp_buffer, decoded.encode());
    EXPECT_TRUE(decoded.has({CamPermission::Speed_Limit, CamPermission::CEN_DSRC_Tolling_Zone}));
    decoded.remove(CamPermission::Speed_Limit).remove(CamPermission::CEN_DSRC_Tolling_Zone);
    EXPECT_TRUE(decoded.none());

    CamPermissions decoded_empty = CamPermissions::decode(ByteBuffer {});
    EXPECT_TRUE(decoded_empty.none());

    CamPermissions decoded_testing = CamPermissions::decode(ByteBuffer {0x00});
    EXPECT_TRUE(decoded_testing.none());

    CamPermissions decoded_version = CamPermissions::decode(ByteBuffer {0xff, 0x80, 0x30});
    EXPECT_TRUE(decoded_version.none());

    CamPermissions decoded_short = CamPermissions::decode(ByteBuffer {0x01, 0x40});
    EXPECT_TRUE(decoded_short.none());

    CamPermissions decoded_long = CamPermissions::decode(ByteBuffer {0x01, 0x80, 0x04, 0x00});
    EXPECT_TRUE(decoded_long.none());

    CamPermissions decoded_reserved = CamPermissions::decode(ByteBuffer {0x01, 0x02, 0x07});
    EXPECT_FALSE(decoded_reserved.none());
    EXPECT_TRUE(decoded_reserved.has(CamPermission::Speed_Limit));
    decoded_reserved.remove(CamPermission::Speed_Limit).remove(CamPermission::Emergency);
    EXPECT_TRUE(std::none_of(all.begin(), all.end(),
                [decoded_reserved](CamPermission cp) { return decoded_reserved.has(cp); }));
    EXPECT_FALSE(decoded_reserved.none());
}

TEST(CamSsp, permissions)
{
    CamPermissions ssp { CamPermission::No_Passing, CamPermission::Speed_Limit };
    std::set<CamPermission> expected { CamPermission::No_Passing, CamPermission::Speed_Limit };
    EXPECT_EQ(expected, ssp.permissions());

    // works also for reserved bits
    const CamPermission reserved = static_cast<CamPermission>(0x0100);
    ssp.add(reserved);
    expected.insert(reserved);
    ASSERT_EQ(3, expected.size());
    EXPECT_EQ(expected, ssp.permissions());
}

TEST(CamSsp, stringify)
{
    EXPECT_EQ("Safety Car", stringify(CamPermission::Safety_Car));
    EXPECT_EQ("Reserved (0x0200)", stringify(static_cast<CamPermission>(0x0200)));
}
