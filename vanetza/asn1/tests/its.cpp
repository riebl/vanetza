#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/cam.hpp>
#include <vanetza/asn1/denm.hpp>
#include <vanetza/asn1/mapem.hpp>
#include <vanetza/asn1/spatem.hpp>
#include <vanetza/asn1/ssem.hpp>
#include <vanetza/asn1/srem.hpp>
#include <vanetza/asn1/ivim.hpp>
#include <vanetza/asn1/vam.hpp>
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

TEST(ItsAsn1, create_srem)
{
    asn1::Srem srem;
}

TEST(ItsAsn1, create_ssem)
{
    asn1::Ssem ssem;
}

TEST(ItsAsn1, create_ivim)
{
    asn1::Ivim ivim;
}

TEST(ItsAsn1, validate_vam)
{
	asn1::r2::Vam vam;

	vam->header.messageId = Vanetza_ITS2_MessageId_vam;
	vam->header.protocolVersion = 2;
	vam->header.stationId = 123;

	vam->vam.generationDeltaTime = 0;
	vam->vam.vamParameters.basicContainer.referencePosition.latitude = Vanetza_ITS2_Latitude_unavailable;
	vam->vam.vamParameters.basicContainer.referencePosition.longitude = Vanetza_ITS2_Longitude_unavailable;
	vam->vam.vamParameters.basicContainer.stationType = 5;

	vam->vam.vamParameters.vruHighFrequencyContainer.heading.value = 0;
	vam->vam.vamParameters.vruHighFrequencyContainer.heading.confidence = Vanetza_ITS2_HeadingConfidence_unavailable;

	vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedValue = 0;
	vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence = Vanetza_ITS2_SpeedConfidence_unavailable;

	EXPECT_TRUE(vam.validate());
}
