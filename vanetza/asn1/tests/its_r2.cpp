#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/r2/EventHistory.h>
#include <vanetza/asn1/its/r2/EventZone.h>
#include <vanetza/asn1/its/r2/HeadingConfidence.h>
#include <vanetza/asn1/its/r2/SituationContainer.h>
#include <vanetza/asn1/its/r2/TimestampIts.h>
#include <vanetza/asn1/vam.hpp>
#include <gtest/gtest.h>

using namespace vanetza;

TEST(ItsAsn1, max_timestamp_roundtrip)
{
    const std::int64_t max_timestamp = 4398046511103;
    asn1::asn1c_wrapper<Vanetza_ITS2_TimestampIts_t> tx { asn_DEF_Vanetza_ITS2_TimestampIts };
    asn_imax2INTEGER(&*tx, max_timestamp);
    auto buffer = tx.encode();
    EXPECT_EQ(6, buffer.size());
    asn1::asn1c_wrapper<Vanetza_ITS2_TimestampIts_t> rx { asn_DEF_Vanetza_ITS2_TimestampIts };
    EXPECT_TRUE(rx.decode(buffer));
    std::int64_t rx_timestamp = 0;
    asn_INTEGER2imax(&*tx, &rx_timestamp);
    EXPECT_EQ(rx_timestamp, max_timestamp);
}

TEST(ItsAsn1R2, validate_vam)
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

TEST(ItsAsn1R2, event_zone)
{
    // just needs to compile (SituationContainer's eventZone is patched)
    Vanetza_ITS2_SituationContainer_t container {};
    container.eventZone = vanetza::asn1::allocate<Vanetza_ITS2_EventZone_t>();
}
