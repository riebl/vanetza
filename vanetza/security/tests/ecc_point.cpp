#include <gtest/gtest.h>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using vanetza::ByteBuffer;
using namespace vanetza::security;
using namespace vanetza;
using namespace std;

EccPoint serialize_roundtrip(EccPoint point)
{
    EccPoint outPoint;
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, point);
    InputArchive ia(stream);
    deserialize(ia, outPoint, PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256);
    return outPoint;
}

TEST(EccPoint, Field_Size)
{
    EXPECT_EQ(32, field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256));
    EXPECT_EQ(32, field_size(PublicKeyAlgorithm::Ecies_Nistp256));
}

TEST(EccPoint_serialize, uncompressed)
{
    EccPoint point = setEccPoint_uncompressed();
    EccPoint outPoint = serialize_roundtrip(point);
    testEccPoint_uncompressed(point, outPoint);
}

TEST(EccPoint_serialize, Compressed_Lsb_Y_0)
{
    EccPoint point = setEccPoint_Compressed_Lsb_Y_0();
    EccPoint outPoint = serialize_roundtrip(point);
    testEccPoint_Compressed_Lsb_Y_0(point, outPoint);
}

TEST(EccPoint_serialize, X_Coordinate_Only)
{
    EccPoint point = setEccPoint_X_Coordinate_Only();
    EccPoint outPoint = serialize_roundtrip(point);
    testEccPoint_X_Coordinate_Only(point, outPoint);
}

TEST(EccPoint_serialize, X_Coordinate_too_Long)
{
    EccPoint point, outPoint, testPoint;
    EccPointType type = EccPointType::X_Coordinate_Only;
    X_Coordinate_Only coord, testCoord;
    for (int c = 0; c < 40; c++) {
        coord.x.push_back(c);
    }
    for (int c = 0; c < 32; c++) {
        testCoord.x.push_back(c);
    }
    point = coord;
    testPoint = testCoord;

    outPoint = serialize_roundtrip(point);

    EccPointType detype = get_type(outPoint);

    EXPECT_EQ(type, detype);
    EXPECT_EQ(boost::get<X_Coordinate_Only>(testPoint).x,
        boost::get<X_Coordinate_Only>(outPoint).x);
}

