#ifndef SETELEMENTS_HPP_CISPFKMVCOSDJ
#define SETELEMENTS_HPP_CISPFKMVCOSDJ

#include <gtest/gtest.h>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/encryption_parameter.hpp>
#include <vanetza/security/header_field.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/recipient_info.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/signer_info.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>
#include <vanetza/security/region.hpp>
#include <vanetza/security/validity_restriction.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

EncryptionKey setSubjectAttribute_Encryption_Key();
std::list<ItsAidSsp> setSubjectAttribute_Its_Aid_Ssp_List();
std::list<IntX> setSubjectAttribute_Its_Aid_List();
std::list<ItsAidPriority> setSubjectAttribute_Priority_Its_Aid_List();
std::list<ItsAidPrioritySsp> setSubjectAttribute_Priority_Ssp_List();

ValidityRestriction setValidityRestriction_Time_End();
ValidityRestriction setValidityRestriction_Time_Start_And_End();
ValidityRestriction setValidityRestriction_Time_Start_And_Duration();
ValidityRestriction setValidityRestriction_Region();

Signature setSignature_Ecdsa_Signature();

SubjectInfo setSubjectInfo();

HashedId8 setSignerInfo_HashedId();
CertificateDigestWithOtherAlgorithm setSignerInfo_CertDigest();
std::list<SignerInfo> setCertificate_SignerInfo();
std::list<SubjectAttribute> setCertificate_SubjectAttributeList();
std::list<ValidityRestriction> setCertificate_ValidityRestriction();
std::list<Certificate> setSignerInfo_CertificateList();

Nonce setEncryptionParemeter_nonce();

RecipientInfo setRecipientInfo();
std::list<RecipientInfo> setRecipientInfoList();

std::list<HashedId3> setHeaderField_hashedList();
ThreeDLocation setHeaderField_threeDLoc();
std::list<RecipientInfo> setHeaderField_RecipientInfoList();
std::list<HeaderField> setHeaderField_list();

std::list<Payload> setPayload_List();

#endif /* SETELEMENTS_HPP_ */
