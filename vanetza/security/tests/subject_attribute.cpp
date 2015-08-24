#include <gtest/gtest.h>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

TEST(SubjectAttribute, serialize)
{
    std::list<SubjectAttribute> list;
    SubjectAttribute sub;

    sub = setSubjectAttribute_Encryption_Key();
    list.push_back(sub);

    SubjectAssurance assurance = 124;
    sub = assurance;
    list.push_back(sub);

    sub = setSubjectAttribute_Its_Aid_List();
    list.push_back(sub);

    sub = setSubjectAttribute_Its_Aid_Ssp_List();
    list.push_back(sub);

    sub = setSubjectAttribute_Priority_Its_Aid_List();
    list.push_back(sub);

    sub = setSubjectAttribute_Priority_Ssp_List();
    list.push_back(sub);
//-----------------------------Serialization---------------------------------------------

    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, list);

    std::list<SubjectAttribute> delist;
    InputArchive ia(stream);
    deserialize(ia, delist);

//---------------------------------TEST------------------------------------------------

    auto it = list.begin();
    auto deIt = delist.begin();

    testSubjectAttribute_Encryption_Key(*it++, *deIt++);
    EXPECT_EQ(get_type(*deIt), SubjectAttributeType::Assurance_Level);
    EXPECT_EQ(boost::get<SubjectAssurance>(*deIt++), boost::get<SubjectAssurance>(*it++));
    testSubjectAttribute_Its_Aid_List(*it++, *deIt++);
    testSubjectAttribute_Its_Aid_Ssp_List(*it++, *deIt++);
    testSubjectAttribute_Priority_Its_Aid_List(*it++, *deIt++);
    testSubjectAttribute_Priority_Ssp_List(*it++, *deIt++);

}

TEST(SubjectAttribute, WebValidator_ItsAidSsp_Size)
{
    std::list<ItsAidSsp> list;
    ItsAidSsp its;
    its.its_aid.set(16512);
    its.service_specific_permissions.push_back(0x01);
    list.push_back(its);

    ItsAidSsp its2;
    its2.its_aid.set(16513);
    its2.service_specific_permissions.push_back(0x01);
    list.push_back(its2);

    EXPECT_EQ(10, get_size(list));
}
