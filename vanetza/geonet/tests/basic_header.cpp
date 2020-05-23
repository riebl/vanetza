#include <gtest/gtest.h>
#include <vanetza/geonet/basic_header.hpp>
#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/tests/serialization.hpp>

using namespace vanetza::geonet;
using vanetza::units::si::seconds;

TEST(BasicHeader, ctor) {
    MIB mib;
    BasicHeader a(mib);
    EXPECT_EQ(a.lifetime, mib.itsGnDefaultPacketLifetime);
    EXPECT_EQ(a.hop_limit, mib.itsGnDefaultHopLimit);

    DataRequest req(mib);
    req.maximum_lifetime.encode(31.0 * seconds);
    req.max_hop_limit = 4;
    BasicHeader b(req, mib);
    EXPECT_EQ(b.lifetime.decode(), 31.0 * seconds);
    EXPECT_EQ(b.hop_limit, 4);

    ShbDataRequest shb(mib);
    BasicHeader c(shb, mib);
    EXPECT_EQ(c.hop_limit, 1);
}

TEST(BasicHeader, serialization) {
    BasicHeader a;
    a.version = 2;
    a.next_header = NextHeaderBasic::Secured;
    a.reserved = 0xC3;
    a.lifetime.raw(0x89);
    a.hop_limit = 218;

    BasicHeader b = serialize_roundtrip(a);
    EXPECT_EQ(a.version, b.version);
    EXPECT_EQ(a.next_header, b.next_header);
    EXPECT_EQ(a.reserved, b.reserved);
    EXPECT_EQ(a.lifetime, b.lifetime);
    EXPECT_EQ(a.hop_limit, b.hop_limit);

    EXPECT_EQ(BasicHeader::length_bytes, serialize_length(a));
}
