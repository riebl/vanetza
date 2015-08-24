#include <vanetza/security/subject_info.hpp>
#include <vanetza/security/tests/test_elements.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <gtest/gtest.h>

using namespace vanetza::security;

SubjectInfo serialize(SubjectInfo sub)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, sub);
    SubjectInfo desub;
    InputArchive ia(stream);
    deserialize(ia, desub);
    return desub;
}

TEST(SubjectInfo, Serialization)
{
    SubjectInfo sub = setSubjectInfo();
    SubjectInfo desub = serialize(sub);
    testSubjectInfo(sub, desub);
}

TEST(SubjectInfo, WebValidator_Size)
{
    SubjectInfo info;
    info.subject_type = SubjectType::Authorization_Ticket;

    EXPECT_EQ(2, get_size(info));
}
