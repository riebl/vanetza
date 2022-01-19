#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/cam.hpp>
#include <vanetza/asn1/denm.hpp>
#include <vanetza/asn1/mapem.hpp>
#include <vanetza/asn1/spatem.hpp>
#include <vanetza/asn1/its/TimestampIts.h>

using namespace vanetza;

TEST(ItsAsn1, max_timestamp_roundtrip)
{
    const std::int64_t max_timestamp = 4398046511103;
    asn1::asn1c_wrapper<TimestampIts_t> tx { asn_DEF_TimestampIts };
    asn_imax2INTEGER(&*tx, max_timestamp);
    auto buffer = tx.encode();
    EXPECT_EQ(6, buffer.size());
    asn1::asn1c_wrapper<TimestampIts_t> rx { asn_DEF_TimestampIts };
    EXPECT_TRUE(rx.decode(buffer));
    std::int64_t rx_timestamp = 0;
    asn_INTEGER2imax(&*tx, &rx_timestamp);
    EXPECT_EQ(rx_timestamp, max_timestamp);
}

TEST(ItsAsn1, encode_denm)
{
    asn1::Denm denm;
    EXPECT_EQ(0, asn_uint642INTEGER(&denm->denm.management.detectionTime, TimestampIts_utcStartOf2004));
    EXPECT_EQ(0, asn_uint642INTEGER(&denm->denm.management.referenceTime, TimestampIts_utcStartOf2004));
    EXPECT_TRUE(denm.validate());
    vanetza::ByteBuffer buf = denm.encode();
    EXPECT_EQ(40, buf.size());
}

TEST(ItsAsn1, create_cam)
{
    asn1::Cam cam;
}

TEST(ItsAsn1, create_denm)
{
    asn1::Denm denm;
}

TEST(ItsAsn1, create_mapem)
{
    asn1::Mapem mapem;
}

TEST(ItsAsn1, create_spatem)
{
    asn1::Spatem spatem;
}
