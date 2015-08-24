#include <gtest/gtest.h>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/signer_info.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza;
using namespace security;

SignerInfo serialize(const SignerInfo& info)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, info);

    SignerInfo deserializedInfo;
    InputArchive ia(stream);
    deserialize(ia, deserializedInfo);
    return deserializedInfo;
}

TEST(SignerInfo, Serialzation)
{
    SignerInfo info;
    info = setSignerInfo_CertificateList();
    SignerInfo deInfo = serialize(info);

    auto it = boost::get<std::list<Certificate>>(info).begin();
    auto deIt = boost::get<std::list<Certificate>>(deInfo).begin();
    testSignerInfo_Certificate(*it++, *deIt++);
    testSignerInfo_Certificate(*it, *deIt);
}

TEST(SignerInfo, WebValidator_Size)
{
    SignerInfo info;
    HashedId8 id {{ 0xA8, 0xED, 0x6D, 0xF6, 0x5B, 0x0E, 0x6D, 0x6A }};
    info = id;

    EXPECT_EQ(9, get_size(info));
}
