#include <vanetza/security/tests/check_ecc_point.hpp>
#include <vanetza/security/tests/check_public_key.hpp>
#include <vanetza/security/tests/check_region.hpp>
#include <vanetza/security/tests/check_subject_info.hpp>
#include <vanetza/security/tests/check_validity_restriction.hpp>
#include <vanetza/security/tests/test_elements.hpp>

void testSubjectAttribute_Encryption_Key(const SubjectAttribute& sub, const SubjectAttribute& deSub)
{
    EncryptionKey key = boost::get<EncryptionKey>(sub);
    EncryptionKey deKey = boost::get<EncryptionKey>(deSub);
    EXPECT_EQ(get_type(deSub), get_type(sub));
    check(key.key, deKey.key);
}

void testSubjectAttribute_Its_Aid_List(const SubjectAttribute& sub, const SubjectAttribute& deSub)
{
    EXPECT_EQ(get_type(deSub), get_type(sub));
    auto iter = boost::get<std::list<IntX>>(deSub).begin();
    for (int c = 0; c < 5; c++) {
        EXPECT_EQ(iter->get(), c + 1000);
        iter++;
    }
}

void testSubjectAttribute_Its_Aid_Ssp_List(const SubjectAttribute& sub,
    const SubjectAttribute& deSub)
{
    EXPECT_EQ(get_type(deSub), get_type(sub));
    int c = 0;
    int c2 = 0;
    for (auto& itsAid : boost::get<std::list<ItsAidSsp>>(deSub)) {
        EXPECT_EQ(itsAid.its_aid.get(), c + 30);
        c2 = 0;
        for (auto& service_specific_permission : itsAid.service_specific_permissions) {
            uint8_t x;
            x = uint8_t(service_specific_permission);
            EXPECT_EQ(int(x), c2 + c);
            c2++;
        }
        c++;
    }
}

void testSignature_Ecdsa_Signature(const Signature& sig, const Signature& deserializedSig)
{
    EXPECT_EQ(get_type(sig), get_type(deserializedSig));
    check(boost::get<EcdsaSignature>(sig).R, boost::get<EcdsaSignature>(deserializedSig).R);
    EXPECT_EQ(boost::get<EcdsaSignature>(sig).s, boost::get<EcdsaSignature>(deserializedSig).s);
}

void testCertificate_SignerInfo(const std::list<SignerInfo>& list,
    const std::list<SignerInfo>& deList)
{
    auto it = list.begin();
    auto deIt = deList.begin();
    EXPECT_EQ(boost::get<HashedId8>(*it++), boost::get<HashedId8>(*deIt++));
    EXPECT_EQ(boost::get<CertificateDigestWithOtherAlgorithm>(*it).algorithm,
        boost::get<CertificateDigestWithOtherAlgorithm>(*deIt).algorithm);
    EXPECT_EQ(boost::get<CertificateDigestWithOtherAlgorithm>(*it).digest,
        boost::get<CertificateDigestWithOtherAlgorithm>(*deIt).digest);
}

void testCertificate_SubjectAttributeList(const std::list<SubjectAttribute>& list,
    const std::list<SubjectAttribute>& deList)
{
    auto it = list.begin();
    auto deIt = deList.begin();
    testSubjectAttribute_Encryption_Key(*it++, *deIt++);
    testSubjectAttribute_Its_Aid_List(*it, *deIt);
}

void testCertificate_ValidityRestrictionList(const std::list<ValidityRestriction>& list,
    const std::list<ValidityRestriction>& deList)
{
    check(list, deList);
}

void testSignerInfo_Certificate(const Certificate& cert, const Certificate& deCert)
{
    EXPECT_EQ(cert.version, deCert.version);
    testCertificate_SignerInfo(cert.signer_info, deCert.signer_info);
    check(cert.subject_info, deCert.subject_info);
    testCertificate_SubjectAttributeList(cert.subject_attributes, deCert.subject_attributes);
    testCertificate_ValidityRestrictionList(cert.validity_restriction, deCert.validity_restriction);
    testSignature_Ecdsa_Signature(cert.signature, deCert.signature);
}

void testHeaderFieldList(const std::list<HeaderField>& list, const std::list<HeaderField>& deList)
{
    auto it = list.begin();
    auto deIt = deList.begin();
    testSignerInfo_Certificate(
        *boost::get<std::list<Certificate>>(boost::get<SignerInfo>(*it++)).begin(),
        *boost::get<std::list<Certificate>>(boost::get<SignerInfo>(*deIt++)).begin());
    EXPECT_EQ(boost::get<Time64>(*it++), boost::get<Time64>(*deIt++));
    EXPECT_EQ(boost::get<Time64WithStandardDeviation>(*it++).time64,
        boost::get<Time64WithStandardDeviation>(*deIt++).time64);
    EXPECT_EQ(boost::get<Time32>(*it++), boost::get<Time32>(*deIt++));
    EXPECT_EQ(static_cast<geonet::geo_angle_i32t>(2 * boost::units::degree::plane_angle()),
        boost::get<ThreeDLocation>(*deIt).longitude);
    EXPECT_EQ(static_cast<geonet::geo_angle_i32t>(1 * boost::units::degree::plane_angle()),
        boost::get<ThreeDLocation>(*deIt).latitude);
    EXPECT_EQ(boost::get<ThreeDLocation>(*it++).elevation,
        boost::get<ThreeDLocation>(*deIt++).elevation);
    EXPECT_EQ(*boost::get<std::list<HashedId3>>(*it++).begin(), *boost::get<std::list<HashedId3>>(*deIt++).begin());
    EXPECT_EQ(boost::get<uint16_t>(*it++), boost::get<uint16_t>(*deIt++));
    EXPECT_EQ(boost::get<Nonce>(boost::get<EncryptionParameter>(*it++)), boost::get<Nonce>(boost::get<EncryptionParameter>(*deIt++)));
    EXPECT_EQ(boost::get<std::list<RecipientInfo>>(*it).begin()->cert_id, boost::get<std::list<RecipientInfo>>(*deIt).begin()->cert_id);
}

