
#include <gtest/gtest.h>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza::security;

TEST(SecuredMessage, Serialization) {
    SecuredMessage m;

    m.protocol_version = 1;
    m.security_profile = Profile::CAM;
    m.headerFields = setHeaderField_list();
    m.payload = setPayload_List();
    std::list<TrailerField> list;
    list.push_back(setSignature_Ecdsa_Signature());
    list.push_back(setSignature_Ecdsa_Signature());
    m.trailerFields = list;

    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, m);

    SecuredMessage deMessage;
    InputArchive ia(stream);
    deserialize(ia, deMessage);

    EXPECT_EQ(m.protocol_version, deMessage.protocol_version);
    EXPECT_EQ(m.security_profile, deMessage.security_profile);
    testHeaderFieldList(m.headerFields, deMessage.headerFields);
    testPayload_list(m.payload, deMessage.payload);
 //   testSignature_Ecdsa_Signature(m.trailerFields.begin(), deMessage.trailerFields.begin());


}
