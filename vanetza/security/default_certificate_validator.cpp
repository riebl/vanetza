#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/security/certificate.hpp>
#include <algorithm>
#include <chrono>

namespace vanetza
{
namespace security
{
namespace
{

boost::optional<StartAndEndValidity> extract_validity_time(const Certificate& certificate)
{
    boost::optional<StartAndEndValidity> restriction;

    for (auto& validity_restriction : certificate.validity_restriction) {
        ValidityRestrictionType type = get_type(validity_restriction);

        if (type == ValidityRestrictionType::Time_Start_And_End) {
            // reject more than one restriction
            if (restriction) {
                return boost::none;
            }
            restriction = boost::get<StartAndEndValidity>(validity_restriction);

            // check if certificate validity restriction timestamps are logically correct
            if (restriction->start_validity >= restriction->end_validity) {
                return boost::none;
            }
        } else if (type == ValidityRestrictionType::Time_End) {
            // must not be used, no certificate profile allows it
            return boost::none;
        } else if (type == ValidityRestrictionType::Time_Start_And_Duration) {
            // must not be used, no certificate profile allows it
            return boost::none;
        }
    }

    return restriction;
}

bool check_time_consistency(const Certificate& certificate, const Certificate& signer)
{
    boost::optional<StartAndEndValidity> certificate_time = extract_validity_time(certificate);
    boost::optional<StartAndEndValidity> signer_time = extract_validity_time(signer);

    if (!certificate_time || !signer_time) {
        return false;
    }

    if (signer_time->start_validity > certificate_time->start_validity) {
        return false;
    }

    if (signer_time->end_validity < certificate_time->end_validity) {
        return false;
    }

    return true;
}

bool check_time_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    boost::optional<StartAndEndValidity> certificate_time = certificate.get_start_and_end_validity();
    boost::optional<StartAndEndValidity> signer_time = signer.get_start_and_end_validity();

    if (!certificate_time || !signer_time) {
        return false;
    }

    if (signer_time->start_validity > certificate_time->start_validity) {
        return false;
    }

    if (signer_time->end_validity < certificate_time->end_validity) {
        return false;
    }

    return true;
}

bool check_time_consistency(const CertificateVariant& certificate, const CertificateVariant& signer)
{

    struct canonical_visitor : public boost::static_visitor<boost::optional<StartAndEndValidity>>
        {
            boost::optional<StartAndEndValidity> operator()(const Certificate& cert) const
            {
                return extract_validity_time(cert);
            }

            boost::optional<StartAndEndValidity> operator()(const CertificateV3& cert) const
            {
                return cert.get_start_and_end_validity();
            }
        };
    boost::optional<StartAndEndValidity> certificate_time = boost::apply_visitor(canonical_visitor(), certificate);//certificate.get_start_and_end_validity();
    boost::optional<StartAndEndValidity> signer_time = boost::apply_visitor(canonical_visitor(), signer);

    if (!certificate_time || !signer_time) {
        return false;
    }

    if (signer_time->start_validity > certificate_time->start_validity) {
        return false;
    }

    if (signer_time->end_validity < certificate_time->end_validity) {
        return false;
    }

    return true;
}

std::list<ItsAid> extract_application_identifiers(const Certificate& certificate)
{
    std::list<ItsAid> aids;

    auto certificate_type = certificate.subject_info.subject_type;
    if (certificate_type == SubjectType::Authorization_Ticket) {
        auto list = certificate.get_attribute<SubjectAttributeType::ITS_AID_SSP_List>();
        if (list) {
            for (auto& item : *list) {
                aids.push_back(item.its_aid.get());
            }
        }
    } else {
        auto list = certificate.get_attribute<SubjectAttributeType::ITS_AID_List>();
        if (list) {
            for (auto& item : *list) {
                aids.push_back(item.get());
            }
        }
    }

    return aids;
}

std::list<ItsAid> extract_application_identifiers(const CertificateV3& certificate)
{
    std::list<ItsAid> aids;
    std::list<PsidSsp_t> psid_ssp_list = certificate.get_app_permissions();
    for (PsidSsp_t psid_ssp : psid_ssp_list){
        aids.push_back(ItsAid(psid_ssp.psid));
        // Check how to handle ssp
        if(psid_ssp.ssp){
            switch (psid_ssp.ssp->present)
            {
            case ServiceSpecificPermissions_PR_opaque:
                // TODO
                break;
            
            case ServiceSpecificPermissions_PR_bitmapSsp:
                //TODO
                break;
            default:
                break;
            }
        }
    }

    return aids;
}

std::list<ItsAid> extract_application_identifiers(const CertificateVariant& certificate){
    struct canonical_visitor : public boost::static_visitor<std::list<ItsAid>>
        {
            std::list<ItsAid> operator()(const Certificate& cert) const
            {
                return extract_application_identifiers(cert);
            }

            std::list<ItsAid> operator()(const CertificateV3& cert) const
            {
                return extract_application_identifiers(cert);
            }
        };
    return boost::apply_visitor(canonical_visitor(), certificate);
}

bool check_permission_consistency_intern(std::list<ItsAid>& certificate_aids, std::list<ItsAid>& signer_aids){
    auto compare = [](ItsAid a, ItsAid b) { return a < b; };

    certificate_aids.sort(compare);
    signer_aids.sort(compare);

    return std::includes(signer_aids.begin(), signer_aids.end(), certificate_aids.begin(), certificate_aids.end());
}

bool check_permission_consistency(const Certificate& certificate, const Certificate& signer)
{
    auto certificate_aids = extract_application_identifiers(certificate);
    auto signer_aids = extract_application_identifiers(signer);
    return check_permission_consistency_intern(certificate_aids, signer_aids);
}

bool check_permission_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    auto certificate_aids = extract_application_identifiers(certificate);
    auto signer_aids = extract_application_identifiers(signer);
    return check_permission_consistency_intern(certificate_aids, signer_aids);
}

bool check_permission_consistency(const CertificateVariant& certificate, const CertificateVariant& signer){
    auto certificate_aids = extract_application_identifiers(certificate);
    auto signer_aids = extract_application_identifiers(signer);
    return check_permission_consistency_intern(certificate_aids, signer_aids);
}

bool check_subject_assurance_consistency_intern(const SubjectAssurance* certificate_assurance, const SubjectAssurance* signer_assurance){
    if (!certificate_assurance || !signer_assurance) {
        return false;
    }

    // See TS 103 096-2 v1.3.1, section 5.2.7.11 + 5.3.5.17 and following
    if (certificate_assurance->assurance() > signer_assurance->assurance()) {
        return false;
    } else if (certificate_assurance->assurance() == signer_assurance->assurance()) {
        if (certificate_assurance->confidence() > signer_assurance->confidence()) {
            return false;
        }
    }

    return true;
}

bool check_subject_assurance_consistency(const Certificate& certificate, const Certificate& signer)
{
    auto certificate_assurance = certificate.get_attribute<SubjectAttributeType::Assurance_Level>();
    auto signer_assurance = signer.get_attribute<SubjectAttributeType::Assurance_Level>();
    return check_subject_assurance_consistency_intern(certificate_assurance, signer_assurance);
    
}

bool check_subject_assurance_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    auto certificate_assurance = certificate.get_subject_assurance();
    auto signer_assurance = signer.get_subject_assurance();
    return check_subject_assurance_consistency_intern(certificate_assurance.get(), signer_assurance.get());
}

bool check_subject_assurance_consistency(const CertificateVariant& certificate, const CertificateVariant& signer){
    struct canonical_visitor : public boost::static_visitor<const SubjectAssurance*>
        {
            const SubjectAssurance* operator()(const Certificate& cert) const
            {
                return cert.get_attribute<SubjectAttributeType::Assurance_Level>();
            }

            const SubjectAssurance* operator()(const CertificateV3& cert) const
            {
                return cert.get_subject_assurance().get();
            }
        };
    auto certificate_assurance = boost::apply_visitor(canonical_visitor(), certificate);
    auto signer_assurance = boost::apply_visitor(canonical_visitor(), signer);
    return check_subject_assurance_consistency_intern(certificate_assurance, signer_assurance);
}

bool check_region_consistency_intern(const GeographicRegion* certificate_region, const GeographicRegion* signer_region) {
    if (!signer_region) {
        return true;
    }

    if (!certificate_region) {
        return false;
    }

    return is_within(*certificate_region, *signer_region);
}


bool check_region_consistency(const Certificate& certificate, const Certificate& signer)
{
    auto certificate_region = certificate.get_restriction<ValidityRestrictionType::Region>();
    auto signer_region = signer.get_restriction<ValidityRestrictionType::Region>();
    return check_region_consistency_intern(certificate_region, signer_region);
    
}

bool check_region_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    auto certificate_region = certificate.get_geographic_region();
    auto signer_region = signer.get_geographic_region();
    return check_region_consistency_intern(certificate_region.get(), signer_region.get());
}

bool check_region_consistency(const CertificateVariant& certificate, const CertificateVariant& signer){
    struct canonical_visitor : public boost::static_visitor<const GeographicRegion*>
        {
            const GeographicRegion* operator()(const Certificate& cert) const
            {
                return cert.get_restriction<ValidityRestrictionType::Region>();
            }

            const GeographicRegion* operator()(const CertificateV3& cert) const
            {
                return cert.get_geographic_region().get();
            }
        };
    auto certificate_region = boost::apply_visitor(canonical_visitor(), certificate);
    auto signer_region = boost::apply_visitor(canonical_visitor(), signer);
    return check_region_consistency_intern(certificate_region, signer_region);
}

bool check_consistency(const Certificate& certificate, const Certificate& signer)
{
    if (!check_time_consistency(certificate, signer)) {
        return false;
    }

    if (!check_permission_consistency(certificate, signer)) {
        return false;
    }

    if (!check_subject_assurance_consistency(certificate, signer)) {
        return false;
    }

    if (!check_region_consistency(certificate, signer)) {
        return false;
    }

    return true;
}

bool check_consistency(const CertificateV3& certificate, const CertificateV3& signer)
{
    if (!check_time_consistency(certificate, signer)) {
        return false;
    }

    if (!check_permission_consistency(certificate, signer)) {
        return false;
    }

    if (!check_subject_assurance_consistency(certificate, signer)) {
        return false;
    }

    if (!check_region_consistency(certificate, signer)) {
        return false;
    }

    return true;
}

bool check_consistency(const CertificateVariant& certificate, const CertificateVariant& signer)
{
    if (!check_time_consistency(certificate, signer)) {
        return false;
    }

    if (!check_permission_consistency(certificate, signer)) {
        return false;
    }

    if (!check_subject_assurance_consistency(certificate, signer)) {
        return false;
    }

    if (!check_region_consistency(certificate, signer)) {
        return false;
    }

    return true;
}

} // namespace

DefaultCertificateValidator::DefaultCertificateValidator(Backend& backend, CertificateCache& cert_cache, const TrustStore& trust_store) :
    m_crypto_backend(backend),
    m_cert_cache(cert_cache),
    m_trust_store(trust_store)
{
}

CertificateValidity DefaultCertificateValidator::check_certificate(const CertificateVariant& certificate){
    class certificate_visitor : public boost::static_visitor<CertificateValidity>
        {
            public:
                certificate_visitor(DefaultCertificateValidator& validator): validator_(validator){}
                CertificateValidity operator()(const Certificate& cert) const
                {
                    return validator_.check_certificate(cert);
                }

                CertificateValidity operator()(const CertificateV3& cert) const
                {
                    return validator_.check_certificate(cert);
                }
            private:
                DefaultCertificateValidator& validator_;
        };
    return boost::apply_visitor(certificate_visitor(*this), certificate);
}


CertificateValidity DefaultCertificateValidator::check_certificate(const Certificate& certificate)
{
    if (!extract_validity_time(certificate)) {
        return CertificateInvalidReason::Broken_Time_Period;
    }

    if (!certificate.get_attribute<SubjectAttributeType::Assurance_Level>()) {
        return CertificateInvalidReason::Missing_Subject_Assurance;
    }

    SubjectType subject_type = certificate.subject_info.subject_type;

    // check if subject_name is empty if certificate is authorization ticket
    if (subject_type == SubjectType::Authorization_Ticket && 0 != certificate.subject_info.subject_name.size()) {
        return CertificateInvalidReason::Invalid_Name;
    }

    if (get_type(certificate.signer_info) != SignerInfoType::Certificate_Digest_With_SHA256) {
        return CertificateInvalidReason::Invalid_Signer;
    }
    HashedId8 signer_hash = boost::get<HashedId8>(certificate.signer_info);

    // try to extract ECDSA signature
    boost::optional<EcdsaSignature> sig = extract_ecdsa_signature(certificate.signature);
    if (!sig) {
        return CertificateInvalidReason::Missing_Signature;
    }

    // create buffer of certificate
    ByteBuffer binary_cert = convert_for_signing(certificate);

    // authorization tickets may only be signed by authorization authorities
    if (subject_type == SubjectType::Authorization_Ticket) {
        for (auto& possible_signer : m_cert_cache.lookup(signer_hash, SubjectType::Authorization_Authority)) {
            auto verification_key = get_public_key(possible_signer, m_crypto_backend);
            if (!verification_key) {
                continue;
            }

            if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
                if (!check_consistency(certificate, possible_signer)) {
                    return CertificateInvalidReason::Inconsistent_With_Signer;
                }

                return CertificateValidity::valid();
            }
        }
    }

    // authorization authorities may only be signed by root CAs
    // Note: There's no clear specification about this, but there's a test for it in 5.2.7.12.4 of TS 103 096-2 V1.3.1
    if (subject_type == SubjectType::Authorization_Authority) {
        for (auto& possible_signer : m_trust_store.lookup(signer_hash)) {
            auto verification_key = get_public_key(possible_signer, m_crypto_backend);
            if (!verification_key) {
                continue;
            }

            if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
                if (!check_consistency(certificate, possible_signer)) {
                    return CertificateInvalidReason::Inconsistent_With_Signer;
                }

                return CertificateValidity::valid();
            }
        }
    }

    return CertificateInvalidReason::Unknown_Signer;
}

CertificateValidity DefaultCertificateValidator::check_certificate(const CertificateV3& certificate)
{

    HashedId8 signer_hash = certificate.get_issuer_identifier();

    if (signer_hash == HashedId8{{0,0,0,0,0,0,0,0}}) {
        return CertificateInvalidReason::Invalid_Signer;
    }

    // try to extract ECDSA signature
    boost::optional<EcdsaSignature> sig = extract_ecdsa_signature(certificate.get_signature());
    if (!sig) {
        return CertificateInvalidReason::Missing_Signature;
    }

    // create buffer of certificate
    ByteBuffer binary_cert = certificate.convert_for_signing();

    // authorization tickets may only be signed by authorization authorities
    
    for (auto& possible_signer : m_cert_cache.lookup(signer_hash)) {
        auto verification_key = get_public_key(possible_signer, m_crypto_backend);
        if (!verification_key) {
            continue;
        }

        if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
            if (!check_consistency(certificate, possible_signer)) {
                return CertificateInvalidReason::Inconsistent_With_Signer;
            }

            return CertificateValidity::valid();
        }
    }

    // authorization authorities may only be signed by root CAs
    // Note: There's no clear specification about this, but there's a test for it in 5.2.7.12.4 of TS 103 096-2 V1.3.1
    for (auto& possible_signer : m_trust_store.lookup(signer_hash)) {
        auto verification_key = get_public_key(possible_signer, m_crypto_backend);
        if (!verification_key) {
            continue;
        }

        if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
            if (!check_consistency(certificate, possible_signer)) {
                return CertificateInvalidReason::Inconsistent_With_Signer;
            }

            return CertificateValidity::valid();
        }
    }

    return CertificateInvalidReason::Unknown_Signer;
}


} // namespace security
} // namespace vanetza
