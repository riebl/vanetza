#include <gtest/gtest.h>
#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza;
using namespace security;

TEST(TrailerField, Serialization) {
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

TEST(WebValidator, Size) {
    TrailerField field;
    Signature sig;
    EcdsaSignature ecdsa;
    EccPoint point;
    X_Coordinate_Only x;

    x.x.push_back(0x37);
    x.x.push_back(0x14);
    x.x.push_back(0x23);
    x.x.push_back(0xBB);
    x.x.push_back(0xA0);
    x.x.push_back(0x90);
    x.x.push_back(0x2d);
    x.x.push_back(0x8a);
    x.x.push_back(0xf2);
    x.x.push_back(0xfb);
    x.x.push_back(0x22);
    x.x.push_back(0x26);
    x.x.push_back(0xd7);
    x.x.push_back(0x3a);
    x.x.push_back(0x77);
    x.x.push_back(0x81);
    x.x.push_back(0xd4);
    x.x.push_back(0xd6);
    x.x.push_back(0xb6);
    x.x.push_back(0x77);
    x.x.push_back(0x26);
    x.x.push_back(0x50);
    x.x.push_back(0xa8);
    x.x.push_back(0xbe);
    x.x.push_back(0xe5);
    x.x.push_back(0xa1);
    x.x.push_back(0xaf);
    x.x.push_back(0x19);
    x.x.push_back(0x8c);
    x.x.push_back(0xed);
    x.x.push_back(0xab);
    x.x.push_back(0xa2);
}
