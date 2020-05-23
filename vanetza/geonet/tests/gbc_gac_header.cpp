#include <gtest/gtest.h>
#include <vanetza/geonet/gbc_gac_header.hpp>
#include <vanetza/geonet/tests/serialization.hpp>
#include <vanetza/units/angle.hpp>

using namespace vanetza::geonet;
using vanetza::geonet::detail::GbcGacHeader;
using vanetza::units::degree;

TEST(GbcGacHeader, ctor) {
    GbcGacHeader hdr;
    EXPECT_EQ(0, static_cast<SequenceNumber::value_type>(hdr.sequence_number));
    EXPECT_EQ(0, hdr.reserved1);
    EXPECT_EQ(LongPositionVector(), hdr.source_position);
    EXPECT_EQ(0, hdr.geo_area_pos_latitude.value());
    EXPECT_EQ(0, hdr.geo_area_pos_longitude.value());
    EXPECT_EQ(0, hdr.distance_a.value());
    EXPECT_EQ(0, hdr.distance_b.value());
    EXPECT_EQ(0, hdr.angle.value());
    EXPECT_EQ(0, hdr.reserved2);
}

TEST(GbcGacHeader, position) {
    GbcGacHeader hdr;
    GeodeticPosition pos { 12.3456789 * degree, 123.4567891 * degree };
    hdr.position(pos);
    EXPECT_EQ(123456789, hdr.geo_area_pos_latitude.value());
    EXPECT_EQ(1234567891, hdr.geo_area_pos_longitude.value());
    EXPECT_EQ(pos.latitude, hdr.position().latitude);
    EXPECT_EQ(pos.longitude, hdr.position().longitude);
}

TEST(GbcGacHeader, serialization) {
    GbcGacHeader a;
    a.sequence_number = SequenceNumber(18);
    a.reserved1 = 0x1234;
    a.source_position.latitude = geo_angle_i32t::from_value(0xAABB);
    a.source_position.longitude = geo_angle_i32t::from_value(0xCCDD);
    a.distance_a = distance_u16t::from_value(0x1234);
    a.distance_b = distance_u16t::from_value(0x4321);
    a.angle = angle_u16t::from_value(0x1337);
    a.reserved2 = 0x2020;

    GbcGacHeader b = serialize_roundtrip(a);
    EXPECT_EQ(a.sequence_number, b.sequence_number);
    EXPECT_EQ(a.reserved1, b.reserved1);
    EXPECT_EQ(a.source_position, b.source_position);
    EXPECT_EQ(a.geo_area_pos_latitude, b.geo_area_pos_latitude);
    EXPECT_EQ(a.geo_area_pos_longitude, b.geo_area_pos_longitude);
    EXPECT_EQ(a.distance_a, b.distance_a);
    EXPECT_EQ(a.distance_b, b.distance_b);
    EXPECT_EQ(a.angle, b.angle);
    EXPECT_EQ(a.reserved2, b.reserved2);

    EXPECT_EQ(GbcGacHeader::length_bytes, serialize_length(a));
}
