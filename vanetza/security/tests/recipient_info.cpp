#include "vanetza/security/recipient_info.hpp"
#include "vanetza/security/tests/set_elements.hpp"
#include "vanetza/security/tests/test_elements.hpp"
#include "gtest/gtest.h"

using namespace vanetza::security;
using namespace std;

RecipientInfo serialize(RecipientInfo info)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, info);

    RecipientInfo deInfo;
    InputArchive ia(stream);
    deserialize(ia, deInfo, SymmetricAlgorithm::Aes128_Ccm);
    return deInfo;
}

std::list<RecipientInfo> serialize(std::list<RecipientInfo> list)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, list);

    std::list<RecipientInfo> deList;
    InputArchive ia(stream);
    deserialize(ia, deList, SymmetricAlgorithm::Aes128_Ccm);
    return deList;
}

TEST(RecipientInfo, Serialize)
{
    RecipientInfo info = setRecipientInfo();
    RecipientInfo deInfo = serialize(info);
    testRecipientInfo(info, deInfo);
}

TEST(RecipientInfoList, Serialize)
{
    std::list<RecipientInfo> list = setRecipientInfoList();
    std::list<RecipientInfo> deList = serialize(list);
    testRecipientInfoList(list, deList);
}
