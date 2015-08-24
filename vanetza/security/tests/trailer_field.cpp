#include <gtest/gtest.h>
#include <stdio.h>
#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>
#include <vanetza/security/tests/web_validator.hpp>

using namespace vanetza;
using namespace security;

TEST(TrailerField, Serialization)
{
    std::list<TrailerField> list;
    list.push_back(setSignature_Ecdsa_Signature());
    list.push_back(setSignature_Ecdsa_Signature());

    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, list);

    std::list<TrailerField> delist;
    InputArchive ia(stream);
    deserialize(ia, delist);

    auto it = list.begin();
    auto deIt = delist.begin();

    testSignature_Ecdsa_Signature(boost::get<Signature>(*it++), boost::get<Signature>(*deIt++));
    testSignature_Ecdsa_Signature(boost::get<Signature>(*it), boost::get<Signature>(*deIt));
}

TEST(TrailerField, WebValidator_Size)
{
    TrailerField field;
    Signature sig;
    EcdsaSignature ecdsa;
    EccPoint point;
    X_Coordinate_Only x;

    byteBuffer_from_string(x.x, "371423BBA0902D8AF2FB2226D73A7781D4D6B6772650A8BEE5A1AF198CEDABA2");
    point = x;
    ecdsa.R = point;

    byteBuffer_from_string(ecdsa.s,
        "C9BF57540C629E6A1E629B8812AEBDDDBCAF472F6586F16C14B3DEFBE9B6ADB2");
    sig = ecdsa;
    field = sig;

    std::list<TrailerField> list;
    list.push_back(field);

    EXPECT_EQ(67, get_size(list));
    EXPECT_EQ(67, get_size(field));
}
