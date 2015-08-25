#include <vanetza/security/tests/web_validator.hpp>
#include <vanetza/security/serialization.hpp>
#include <sstream>
#include <gtest/gtest.h>

using namespace vanetza;
using namespace security;

void stream_from_string(std::stringstream& stream, const char *string)
{
    unsigned n;
    OutputArchive oa(stream);
    for (size_t i = 0; i < strlen(string) / 2; i++) {
        sscanf(string + 2 * i, "%2X", &n);
        uint8_t tmp = (char) n;
        oa << tmp;
    }
}

void byteBuffer_from_string(ByteBuffer& buf, const char *string)
{
    unsigned n;
    for (size_t i = 0; i < strlen(string) / 2; i++) {
        sscanf(string + 2 * i, "%2X", &n);
        uint8_t tmp = (char) n;
        buf.push_back(tmp);
    }
}

std::list<SubjectAttribute> SetWebValidator_SecuredMessage3_Attribute()
{
    std::list<SubjectAttribute> list;
    SubjectAttribute sub;
    VerificationKey key;
    ecdsa_nistp256_with_sha256 ecdsa;
    Uncompressed un;

    byteBuffer_from_string(un.x,
        "0209B0434163CCBAFDD34A45333E418FB96C05BBE0E7E1D755D40D0B4BBE8DA5");
    byteBuffer_from_string(un.y,
        "08EC2F2723B7ADF0F27C39F3AECFF0783C196F9961F8821E6294375D9294CD6A");

    ecdsa.public_key = un;
    key.key = ecdsa;
    sub = key;
    list.push_back(sub);

    EXPECT_EQ(67, get_size(list));

    EncryptionKey encKey;
    Uncompressed un2;

    byteBuffer_from_string(un2.x,
        "52113CE698DB081491675DF8FFE81C23EA5D0071B2D2BF0E0DA4ADA0CDA58259");
    byteBuffer_from_string(un2.y,
        "CA5D999200B6565E194EDAB8BD3DCA863F2DDF39C13E7A0375ECE2566C5EB8C6");

    ecdsa.public_key = un2;
    encKey.key = ecdsa;
    sub = encKey;
    list.push_back(sub);
    EXPECT_EQ(134, get_size(list));

    SubjectAssurance assu = 0x00;
    sub = assu;
    list.push_back(sub);

    EXPECT_EQ(136, get_size(list));

    std::list<ItsAidSsp> sspList;
    ItsAidSsp its;
    its.its_aid.set(16512);
    its.service_specific_permissions.push_back(0x01);
    sspList.push_back(its);

    ItsAidSsp its2;
    its2.its_aid.set(16513);
    its2.service_specific_permissions.push_back(0x01);
    sspList.push_back(its2);
    sub = sspList;

    list.push_back(sub);
    EXPECT_EQ(148, get_size(list));
    return list;
}

std::list<ValidityRestriction> setWebValidator_SecuredMessage3_Restriction()
{
    std::list<ValidityRestriction> list;
    ValidityRestriction res;
    StartAndEndValidity start;
    start.start_validity = 12345;
    start.end_validity = 4786283;
    res = start;

    list.push_back(res);

    GeographicRegion reg;
    IdentifiedRegion id;
    id.region_dictionary = RegionDictionary::Un_Stats;
    id.region_identifier = 150;
    id.local_region.set(0);

    reg = id;
    res = reg;
    list.push_back(res);
    return list;
}

Signature setWebValidator_SecuredMessage3_Signature()
{
    Signature sig;
    EcdsaSignature eSig;
    X_Coordinate_Only x;

    byteBuffer_from_string(x.x, "8DA1F3F9F35E04C3DE77D7438988A8D57EBE44DAA021A4269E297C177C9CFE45");
    eSig.R = x;

    byteBuffer_from_string(eSig.s,
        "8E128EC290785D6631961625020943B6D87DAA54919A98F7865709929A7C6E48");
    sig = eSig;
    return sig;
}
