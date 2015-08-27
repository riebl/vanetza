#ifndef TEST_ELEMENTS_HPP_KISBVCLSDSICN
#define TEST_ELEMENTS_HPP_KISBVCLSDSICN

#include <gtest/gtest.h>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/encryption_parameter.hpp>
#include <vanetza/security/header_field.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/recipient_info.hpp>
#include <vanetza/security/region.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/signer_info.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>
#include <vanetza/security/validity_restriction.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

void testSubjectAttribute_Encryption_Key(const SubjectAttribute&, const SubjectAttribute&);
void testSubjectAttribute_Its_Aid_List(const SubjectAttribute&, const SubjectAttribute&);
void testSubjectAttribute_Its_Aid_Ssp_List(const SubjectAttribute&, const SubjectAttribute&);
void testSubjectAttribute_Priority_Its_Aid_List(const SubjectAttribute&, const SubjectAttribute&);
void testSubjectAttribute_Priority_Ssp_List(const SubjectAttribute&, const SubjectAttribute&);

void testValidityRestriction_Time_End(const ValidityRestriction&, const ValidityRestriction&);
void testValidityRestriction_Time_Start_And_End(const ValidityRestriction&,
    const ValidityRestriction&);
void testValidityRestriction_Time_Start_And_Duration(const ValidityRestriction&,
    const ValidityRestriction&);
void testValidityRestriction_Region(const ValidityRestriction&, const ValidityRestriction&);

void testSignature_Ecdsa_Signature(const Signature&, const Signature&);

void testSubjectInfo(const SubjectInfo&, const SubjectInfo&);

void testCertificate_SignerInfo(const std::list<SignerInfo>&, const std::list<SignerInfo>&);
void testCertificate_SubjectAttributeList(const std::list<SubjectAttribute>&,
    const std::list<SubjectAttribute>&);
void testCertificate_ValidityRestrictionList(const std::list<ValidityRestriction>&,
    const std::list<ValidityRestriction>&);
void testSignerInfo_Certificate(const Certificate&, const Certificate&);

void testEncryptionParemeter_nonce(const EncryptionParameter&, const EncryptionParameter&);

void testRecipientInfo(const RecipientInfo&, const RecipientInfo&);
void testRecipientInfoList(const std::list<RecipientInfo>&, const std::list<RecipientInfo>&);

void testHeaderFieldList(const std::list<HeaderField>& list, const std::list<HeaderField>& deList);

void testPayload_list(const std::list<Payload>&, const std::list<Payload>&);

#endif /* TEST_ELEMENTS_HPP_KISBVCLSDSICN */
