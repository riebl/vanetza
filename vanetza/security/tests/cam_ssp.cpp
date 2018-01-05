#include <vanetza/security/cam_ssp.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <set>

using vanetza::ByteBuffer;
using namespace vanetza::security;

static const std::set<CamPermission> all {{
    CamPermission::CenDsrcTollingZone,
    CamPermission::PublicTransport,
    CamPermission::SpecialTransport,
    CamPermission::DangerousGoods,
    CamPermission::Roadwork,
    CamPermission::Rescue,
    CamPermission::Emergency,
    CamPermission::SafetyCar,
    CamPermission::ClosedLanes,
    CamPermission::RequestForRightOfWay,
    CamPermission::RequestForFreeCrossingAtTrafficLight,
    CamPermission::NoPassing,
    CamPermission::NoPassingForTrucks,
    CamPermission::SpeedLimit,
}};

TEST(CamSsp, empty)
{
    CamPermissions empty;
    EXPECT_TRUE(std::none_of(all.begin(), all.end(), [empty](CamPermission cp) { return empty.has(cp); }));
    EXPECT_TRUE(empty.none());
}

TEST(CamSsp, single)
{
    CamPermissions single(CamPermission::SafetyCar);
    EXPECT_FALSE(single.none());
    EXPECT_TRUE(single.has(CamPermission::SafetyCar));

    std::set<CamPermission> rest = all;
    rest.erase(CamPermission::SafetyCar);
    EXPECT_TRUE(std::none_of(rest.begin(), rest.end(), [single](CamPermission cp) { return single.has(cp); }));
}

TEST(CamSsp, multiple)
{
    CamPermissions multiple({CamPermission::Roadwork, CamPermission::PublicTransport, CamPermission::SpeedLimit});
    EXPECT_TRUE(multiple.has(CamPermission::Roadwork));
    EXPECT_TRUE(multiple.has(CamPermission::PublicTransport));
    EXPECT_TRUE(multiple.has(CamPermission::SpeedLimit));
    EXPECT_TRUE(multiple.has({CamPermission::Roadwork, CamPermission::PublicTransport, CamPermission::SpeedLimit}));
}

TEST(CamSsp, manipulation)
{
    CamPermissions ssp({CamPermission::NoPassing, CamPermission::Rescue});
    EXPECT_TRUE(ssp.has({CamPermission::Rescue, CamPermission::NoPassing}));
    ssp.remove(CamPermission::Rescue);
    EXPECT_FALSE(ssp.has({CamPermission::Rescue, CamPermission::NoPassing}));
    EXPECT_TRUE(ssp.has(CamPermission::NoPassing));

    ssp.remove(CamPermission::SpeedLimit);
    EXPECT_FALSE(ssp.has(CamPermission::SpeedLimit));
    EXPECT_TRUE(ssp.has(CamPermission::NoPassing));

    ssp.add(CamPermission::ClosedLanes);
    EXPECT_TRUE(ssp.has({CamPermission::ClosedLanes, CamPermission::NoPassing}));
    ssp.remove(CamPermission::NoPassing).remove(CamPermission::ClosedLanes);
    EXPECT_TRUE(ssp.none());
}

TEST(CamSsp, serialization)
{
    CamPermissions ssp;
    const auto empty_ssp_buffer = ssp.encode();
    EXPECT_EQ(ByteBuffer({0x01, 0x00, 0x00}), empty_ssp_buffer);

    ssp.add(CamPermission::CenDsrcTollingZone);
    const auto dsrc_ssp_buffer = ssp.encode();
    EXPECT_EQ(ByteBuffer({0x01, 0x80, 0x00}), dsrc_ssp_buffer);

    ssp.add(CamPermission::SpeedLimit);
    const auto extremes_ssp_buffer = ssp.encode();
    EXPECT_EQ(ByteBuffer({0x01, 0x80, 0x04}), extremes_ssp_buffer);

    CamPermissions decoded = CamPermissions::decode(extremes_ssp_buffer);
    EXPECT_EQ(extremes_ssp_buffer, decoded.encode());
    EXPECT_TRUE(decoded.has({CamPermission::SpeedLimit, CamPermission::CenDsrcTollingZone}));
    decoded.remove(CamPermission::SpeedLimit).remove(CamPermission::CenDsrcTollingZone);
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
    EXPECT_TRUE(decoded_reserved.has(CamPermission::SpeedLimit));
    decoded_reserved.remove(CamPermission::SpeedLimit).remove(CamPermission::Emergency);
    EXPECT_TRUE(std::none_of(all.begin(), all.end(),
                [decoded_reserved](CamPermission cp) { return decoded_reserved.has(cp); }));
    EXPECT_FALSE(decoded_reserved.none());
}

TEST(CamSsp, permissions)
{
    CamPermissions ssp { CamPermission::NoPassing, CamPermission::SpeedLimit };
    std::set<CamPermission> expected { CamPermission::NoPassing, CamPermission::SpeedLimit };
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
    EXPECT_EQ("Safety Car", stringify(CamPermission::SafetyCar));
    EXPECT_EQ("Reserved (0x0200)", stringify(static_cast<CamPermission>(0x0200)));
}
