#include <gtest/gtest.h>
#include <vanetza/asn1/cpm.hpp>

using namespace vanetza;

TEST(Cpm, decode_plain)
{
    // generated with https://asn1.io/asn1playground
    // contains a minimum set of fields, i.e. no optional containers
    static const ByteBuffer cpm_uper = {
        0x01, 0xff, 0x00, 0x00, 0x05, 0x39, 0x00, 0x2a, 0x00, 0x03, 0x49, 0x04,
        0x84, 0x01, 0xc7, 0x61, 0x26, 0x00, 0x7d, 0x03, 0xe8, 0xe1, 0x36, 0xee,
        0x87, 0xc0, 0xc0
    };

    asn1::Cpm cpm;
    ASSERT_TRUE(cpm.decode(cpm_uper));

    EXPECT_EQ(1, cpm->header.protocolVersion);
    EXPECT_EQ(255, cpm->header.messageID);
    EXPECT_EQ(1337, cpm->header.stationID);

    EXPECT_EQ(42, cpm->cpm.generationDeltaTime);
    EXPECT_EQ(3, cpm->cpm.cpmParameters.numberOfPerceivedObjects);

    const auto& mgmt = cpm->cpm.cpmParameters.managementContainer;
    EXPECT_EQ(1, mgmt.stationType);
    EXPECT_EQ(480000000, mgmt.referencePosition.latitude);
    EXPECT_EQ(110000000, mgmt.referencePosition.longitude);
    EXPECT_EQ(800001, mgmt.referencePosition.altitude.altitudeValue);
    EXPECT_EQ(AltitudeConfidence_unavailable, mgmt.referencePosition.altitude.altitudeConfidence);
    EXPECT_EQ(500, mgmt.referencePosition.positionConfidenceEllipse.semiMajorConfidence);
    EXPECT_EQ(250, mgmt.referencePosition.positionConfidenceEllipse.semiMinorConfidence);
    EXPECT_EQ(900, mgmt.referencePosition.positionConfidenceEllipse.semiMajorOrientation);
}

TEST(Cpm, decode_one_perceived_object)
{
    // generated with https://asn1.io/asn1playground
    // contains a single perceived object container
    static const ByteBuffer cpm_uper = {
      0x01, 0xff, 0x00, 0x00, 0x05, 0x39, 0x00, 0x2a, 0x10, 0x03, 0x49, 0x04,
      0x84, 0x01, 0xc7, 0x61, 0x26, 0x00, 0x7d, 0x03, 0xe8, 0xe1, 0x36, 0xee,
      0x87, 0xc0, 0x0c, 0x00, 0x01, 0x8e, 0x10, 0x7d, 0x0a, 0x2c, 0x9f, 0x0c,
      0x89, 0xa1, 0x21, 0x94, 0x00, 0xef, 0xd0, 0x07, 0x7f, 0x01, 0x80
    };

    asn1::Cpm cpm;
    ASSERT_TRUE(cpm.decode(cpm_uper));

    ASSERT_TRUE(cpm->cpm.cpmParameters.perceivedObjectContainer);
    EXPECT_EQ(1, cpm->cpm.cpmParameters.perceivedObjectContainer->list.count);

    const PerceivedObject_t* object = cpm->cpm.cpmParameters.perceivedObjectContainer->list.array[0];
    ASSERT_TRUE(object);
    EXPECT_EQ(12, object->objectID);
    EXPECT_EQ(300, object->timeOfMeasurement);
    ASSERT_TRUE(object->objectAge);
    EXPECT_EQ(500, *object->objectAge);
    EXPECT_EQ(20, object->objectConfidence);
    EXPECT_EQ(50000, object->xDistance.value);
    EXPECT_EQ(100, object->xDistance.confidence);
    EXPECT_EQ(25000, object->yDistance.value);
    EXPECT_EQ(50, object->yDistance.confidence);
    EXPECT_FALSE(object->zDistance);
    EXPECT_EQ(15, object->xSpeed.value);
    EXPECT_EQ(127, object->xSpeed.confidence);
    EXPECT_EQ(30, object->ySpeed.value);
    EXPECT_EQ(127, object->ySpeed.confidence);
}

TEST(Cpm, roundtrip)
{
    // same payload as in decode_one_perceived_object test
    static const ByteBuffer cpm_uper = {
      0x01, 0xff, 0x00, 0x00, 0x05, 0x39, 0x00, 0x2a, 0x10, 0x03, 0x49, 0x04,
      0x84, 0x01, 0xc7, 0x61, 0x26, 0x00, 0x7d, 0x03, 0xe8, 0xe1, 0x36, 0xee,
      0x87, 0xc0, 0x0c, 0x00, 0x01, 0x8e, 0x10, 0x7d, 0x0a, 0x2c, 0x9f, 0x0c,
      0x89, 0xa1, 0x21, 0x94, 0x00, 0xef, 0xd0, 0x07, 0x7f, 0x01, 0x80
    };
    asn1::Cpm cpm;
    EXPECT_TRUE(cpm.decode(cpm_uper));
    EXPECT_EQ(cpm_uper, cpm.encode());
}

TEST(Cpm, encode_one_perceived_object)
{
    asn1::Cpm cpm;
    cpm->cpm.cpmParameters.numberOfPerceivedObjects = 1;
    cpm->cpm.cpmParameters.perceivedObjectContainer = asn1::allocate<PerceivedObjectContainer_t>();

    auto object = asn1::allocate<PerceivedObject_t>();
    EXPECT_EQ(0, ASN_SEQUENCE_ADD(cpm->cpm.cpmParameters.perceivedObjectContainer, object));
    EXPECT_EQ(1, cpm->cpm.cpmParameters.perceivedObjectContainer->list.count);
    EXPECT_EQ(object, cpm->cpm.cpmParameters.perceivedObjectContainer->list.array[0]);

    object->objectID = 1;
    object->timeOfMeasurement = TimeOfMeasurement_oneMilliSecond;
    object->xDistance.value = DistanceValue_oneMeter;
    object->xDistance.confidence = DistanceConfidence_unavailable;
    object->yDistance.value = DistanceValue_oneMeter;
    object->yDistance.confidence = DistanceConfidence_unavailable;
    object->xSpeed.value = SpeedValueExtended_unavailable;
    object->xSpeed.confidence = SpeedConfidence_unavailable;
    object->ySpeed.value = SpeedValueExtended_unavailable;
    object->ySpeed.confidence = SpeedConfidence_unavailable;

    EXPECT_TRUE(cpm.validate());
    EXPECT_FALSE(cpm.encode().empty());
}

