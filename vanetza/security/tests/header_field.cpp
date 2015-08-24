#include <gtest/gtest.h>
#include <vanetza/security/header_field.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/geonet/units.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>
#include <vanetza/security/tests/web_validator.cpp>

using namespace std;
using namespace vanetza::security;
using namespace vanetza;

std::list<HeaderField> serialize(std::list<HeaderField> list)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, list);
    std::list<HeaderField> deList;
    InputArchive ia(stream);
    deserialize(ia, deList);
    return deList;
}

TEST(HeaderField, Serialize)
{
    std::list<HeaderField> list = setHeaderField_list();
    std::list<HeaderField> deList = serialize(list);
    testHeaderFieldList(list, deList);
}

TEST(HeaderField, WebValidator_SecuredMessage3_Size)
{
    std::list<HeaderField> list;
    HeaderField field1;
    std::list<SignerInfo> infoList1;
    SignerInfo info1;
    Certificate cert1;
    cert1.version = uint8_t(1);
    //-------------------- signer info
    HashedId8 id1 {{ 0xA8, 0xED, 0x6D, 0xF6, 0x5B, 0x0E, 0x6D, 0x6A }};
    info1 = id1;
    infoList1.push_back(info1);
    cert1.signer_info = infoList1;

    //-------------------- subject_info

    SubjectInfo subInfo1;
    subInfo1.subject_type = SubjectType::Authorization_Ticket;
    cert1.subject_info = subInfo1;

    //-------------------- subject_attribute

    cert1.subject_attributes = SetWebValidator_SecuredMessage3_Attribute();

    //-------------------- validity_restriction

    cert1.validity_restriction = setWebValidator_SecuredMessage3_Restriction();

    //-------------------- signature

    cert1.signature = setWebValidator_SecuredMessage3_Signature();
    info1 = cert1;
    field1 = info1;
    list.push_back(field1);
    EXPECT_EQ(247, get_size(list));

    Time64 time64 = 0x1111111111111111;
    field1 = time64;
    list.push_back(field1);
    uint16_t elem = 0x1111;
    field1 = elem;
    list.push_back(field1);

    EXPECT_EQ(259, get_size(list));

}

