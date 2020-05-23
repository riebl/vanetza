#include <gtest/gtest.h>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/tests/serialization.hpp>

using namespace vanetza::geonet;

TEST(CommonHeader, ctor) {
    MIB mib;
    CommonHeader a(mib);
    EXPECT_EQ(a.traffic_class.raw(), mib.itsGnDefaultTrafficClass.raw());
    EXPECT_EQ(a.maximum_hop_limit, mib.itsGnDefaultHopLimit);
    EXPECT_EQ(a.payload, 0);

    DataRequest req(mib);
    req.upper_protocol = UpperProtocol::BTP_B;
    req.max_hop_limit = 3;
    req.traffic_class.store_carry_forward(true);
    CommonHeader b(req, mib);
    EXPECT_EQ(b.next_header, NextHeaderCommon::BTP_B);
    EXPECT_EQ(b.maximum_hop_limit, 3);
    EXPECT_TRUE(b.traffic_class.store_carry_forward());

    ShbDataRequest shb(mib);
    CommonHeader c(shb, mib);
    EXPECT_EQ(c.header_type, HeaderType::TSB_Single_Hop);
    EXPECT_EQ(c.maximum_hop_limit, 1);
}

TEST(CommonHeader, serialization) {
    CommonHeader a;
    a.next_header = NextHeaderCommon::IPv6;
    a.reserved1 = 12;
    a.header_type = HeaderType::GeoAnycast_Elip;
    a.traffic_class = TrafficClass(0xAB);
    a.flags = 0x18;
    a.payload = 0x1234;
    a.maximum_hop_limit = 0x78;
    a.reserved2 = 0x56;

    CommonHeader b = serialize_roundtrip(a);
    EXPECT_EQ(a.next_header, b.next_header);
    EXPECT_EQ(a.reserved1, b.reserved1);
    EXPECT_EQ(a.header_type, b.header_type);
    EXPECT_EQ(a.traffic_class.raw(), b.traffic_class.raw());
    EXPECT_EQ(a.flags, b.flags);
    EXPECT_EQ(a.payload, b.payload);
    EXPECT_EQ(a.maximum_hop_limit, b.maximum_hop_limit);
    EXPECT_EQ(a.reserved2, b.reserved2);

    EXPECT_EQ(CommonHeader::length_bytes, serialize_length(a));
}
