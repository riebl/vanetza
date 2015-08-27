#include <vanetza/security/tests/check_ecc_point.hpp>
#include <vanetza/security/tests/check_public_key.hpp>
#include <vanetza/security/tests/check_region.hpp>
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

void testSubjectAttribute_Priority_Its_Aid_List(const SubjectAttribute& sub,
    const SubjectAttribute& deSub)
{
    EXPECT_EQ(get_type(deSub), get_type(sub));
    int c = 0;
    for (auto& itsAidPriorityList : boost::get<std::list<ItsAidPriority>>(deSub)) {
        EXPECT_EQ(itsAidPriorityList.its_aid.get(), c + 35);
        EXPECT_EQ(itsAidPriorityList.max_priority, (125 + c));
        c++;
    }
}

void testSubjectAttribute_Priority_Ssp_List(const SubjectAttribute& sub,
    const SubjectAttribute& deSub)
{
    EXPECT_EQ(get_type(deSub), get_type(sub));
    auto iter = boost::get<std::list<ItsAidPrioritySsp>>(deSub).begin();
    EXPECT_EQ(iter->its_aid.get(), 10);
    EXPECT_EQ(iter->max_priority, 15);
    auto buf_it = iter->service_specific_permissions.begin();
    for (int c = 0; c < 5; c++) {
        uint8_t x;
        x = uint8_t(*buf_it);
        EXPECT_EQ(x, c + 100);
        buf_it++;
    }
    iter++;
    EXPECT_EQ(iter->its_aid.get(), 12);
    EXPECT_EQ(iter->max_priority, 125);
    buf_it = iter->service_specific_permissions.begin();
    for (int c = 0; c < 7; c++) {
        uint8_t x;
        x = uint8_t(*buf_it);
        EXPECT_EQ(int(x), c + 200);
        buf_it++;
    }
}

void testValidityRestriction_Time_End(const ValidityRestriction& res,
    const ValidityRestriction& deserializedRes)
{
    EXPECT_EQ(get_type(res), get_type(deserializedRes));
    EXPECT_EQ(boost::get<EndValidity>(res), boost::get<EndValidity>(deserializedRes));
}

void testValidityRestriction_Time_Start_And_End(const ValidityRestriction& res,
    const ValidityRestriction& deserializedRes)
{
    EXPECT_EQ(get_type(res), get_type(deserializedRes));
    EXPECT_EQ(boost::get<StartAndEndValidity>(res).end_validity,
        boost::get<StartAndEndValidity>(deserializedRes).end_validity);
    EXPECT_EQ(boost::get<StartAndEndValidity>(res).start_validity,
        boost::get<StartAndEndValidity>(deserializedRes).start_validity);
}

void testValidityRestriction_Time_Start_And_Duration(const ValidityRestriction& res,
    const ValidityRestriction& deserializedRes)
{
    EXPECT_EQ(get_type(res), get_type(deserializedRes));
    EXPECT_EQ(boost::get<StartAndDurationValidity>(res).start_validity,
        boost::get<StartAndDurationValidity>(deserializedRes).start_validity);
    Duration a = boost::get<StartAndDurationValidity>(res).duration;
    Duration b = boost::get<StartAndDurationValidity>(deserializedRes).duration;
    EXPECT_EQ(a.raw(), b.raw());
}

void testValidityRestriction_Region(const ValidityRestriction& res,
    const ValidityRestriction& deserializedRes)
{
    EXPECT_EQ(get_type(res), get_type(deserializedRes));
    check(boost::get<GeographicRegion>(res), boost::get<GeographicRegion>(deserializedRes));
}

void testSignature_Ecdsa_Signature(const Signature& sig, const Signature& deserializedSig)
{
    EXPECT_EQ(get_type(sig), get_type(deserializedSig));
    check(boost::get<EcdsaSignature>(sig).R, boost::get<EcdsaSignature>(deserializedSig).R);
    EXPECT_EQ(boost::get<EcdsaSignature>(sig).s, boost::get<EcdsaSignature>(deserializedSig).s);
}

void testSubjectInfo(const SubjectInfo& sub, const SubjectInfo& desub)
{
    EXPECT_EQ(sub.subject_name.size(), get_size(sub) - 2);
    EXPECT_EQ(sub.subject_name.size(), desub.subject_name.size());
    EXPECT_EQ(sub.subject_type, desub.subject_type);
    EXPECT_EQ(sub.subject_name, desub.subject_name);
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
    auto it = list.begin();
    auto deIt = deList.begin();
    testValidityRestriction_Region(*it++, *deIt++);
    testValidityRestriction_Time_Start_And_End(*it++, *deIt++);
    testValidityRestriction_Time_Start_And_Duration(*it++, *deIt++);
}

void testSignerInfo_Certificate(const Certificate& cert, const Certificate& deCert)
{
    EXPECT_EQ(cert.version, deCert.version);
    testCertificate_SignerInfo(cert.signer_info, deCert.signer_info);
    testSubjectInfo(cert.subject_info, deCert.subject_info);
    testCertificate_SubjectAttributeList(cert.subject_attributes, deCert.subject_attributes);
    testCertificate_ValidityRestrictionList(cert.validity_restriction, deCert.validity_restriction);
    testSignature_Ecdsa_Signature(cert.signature, deCert.signature);
}

void testEncryptionParemeter_nonce(const EncryptionParameter& param,
    const EncryptionParameter& deParam)
{
    EXPECT_EQ(get_type(param), get_type(deParam));
    Nonce a = boost::get<Nonce>(param);
    Nonce b = boost::get<Nonce>(deParam);
    EXPECT_EQ(a, b);
}

void testRecipientInfo(const RecipientInfo& info, const RecipientInfo& deInfo)
{
    EXPECT_EQ(info.cert_id, deInfo.cert_id);
    EXPECT_EQ(boost::get<EciesNistP256EncryptedKey>(info.enc_key).c,
        boost::get<EciesNistP256EncryptedKey>(deInfo.enc_key).c);
    EXPECT_EQ(boost::get<EciesNistP256EncryptedKey>(info.enc_key).t,
        boost::get<EciesNistP256EncryptedKey>(deInfo.enc_key).t);
    check(boost::get<EciesNistP256EncryptedKey>(info.enc_key).v,
        boost::get<EciesNistP256EncryptedKey>(deInfo.enc_key).v);
}

void testRecipientInfoList(const std::list<RecipientInfo>& list,
    const std::list<RecipientInfo>& deList)
{
    auto it = list.begin();
    auto deIt = deList.begin();
    testRecipientInfo(*it++, *deIt++);
    testRecipientInfo(*it, *deIt);
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

void testPayload_list(const std::list<Payload>& list, const std::list<Payload>& deList)
{
    auto it = list.begin();
    auto deIt = deList.begin();

    EXPECT_EQ((*it++).buffer, (*deIt++).buffer);
    EXPECT_EQ((*it++).buffer, (*deIt++).buffer);
    EXPECT_EQ((*it).buffer, (*deIt).buffer);
}
