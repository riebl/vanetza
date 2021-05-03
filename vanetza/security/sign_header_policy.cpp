#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/sign_service.hpp>
#include <list>

namespace vanetza
{
namespace security
{

DefaultSignHeaderPolicy::DefaultSignHeaderPolicy(const Runtime& rt, PositionProvider& positioning) :
    m_runtime(rt), m_positioning(positioning), m_cam_next_certificate(m_runtime.now()), m_cert_requested(false), m_chain_requested(false)
{
}

std::list<HeaderField> DefaultSignHeaderPolicy::prepare_header(const SignRequest& request, CertificateProvider& certificate_provider)
{
    std::list<HeaderField> header_fields;

    header_fields.push_back(convert_time64(m_runtime.now()));
    header_fields.push_back(IntX(request.its_aid));

    if (request.its_aid == aid::CA) {
        // section 7.1 in TS 103 097 v1.2.1
        if (m_chain_requested) {
            std::list<Certificate> full_chain;
            full_chain.splice(full_chain.end(), certificate_provider.own_chain());
            full_chain.push_back(certificate_provider.own_certificate());
            header_fields.push_back(SignerInfo { std::move(full_chain) });
            m_cam_next_certificate = m_runtime.now() + std::chrono::seconds(1);
        } else if (m_runtime.now() < m_cam_next_certificate && !m_cert_requested) {
            header_fields.push_back(SignerInfo { calculate_hash(certificate_provider.own_certificate()) });
        } else {
            header_fields.push_back(SignerInfo { certificate_provider.own_certificate() });
            m_cam_next_certificate = m_runtime.now() + std::chrono::seconds(1);
        }

        if (m_unknown_certificates.size() > 0) {
            std::list<HashedId3> unknown_certificates(m_unknown_certificates.begin(), m_unknown_certificates.end());
            header_fields.push_back(unknown_certificates);
            m_unknown_certificates.clear();
        }

        m_cert_requested = false;
        m_chain_requested = false;
    } else {
        auto position = m_positioning.position_fix();
        if (position.altitude) {
            header_fields.push_back(ThreeDLocation(position.latitude, position.longitude, to_elevation(position.altitude->value())));
        } else {
            header_fields.push_back(ThreeDLocation(position.latitude, position.longitude));
        }
        header_fields.push_back(SignerInfo { certificate_provider.own_certificate() });
    }

    // ensure correct serialization order, see TS 103 097 v1.2.1
    header_fields.sort([](const HeaderField& a, const HeaderField& b) {
        const HeaderFieldType type_a = get_type(a);
        const HeaderFieldType type_b = get_type(b);

        // signer_info must be encoded first in all profiles
        if (type_a == HeaderFieldType::Signer_Info) {
            // return false if both are signer_info fields
            return type_b != HeaderFieldType::Signer_Info;
        } else if (type_b == HeaderFieldType::Signer_Info) {
            return false; // "signer info" @ b has precedence over "non-signer info" @ a
        }

        // all other fields must be encoded in ascending order
        using enum_int = std::underlying_type<HeaderFieldType>::type;
        return static_cast<enum_int>(type_a) < static_cast<enum_int>(type_b);
    });

    return header_fields;
}

void DefaultSignHeaderPolicy::request_unrecognized_certificate(HashedId8 id)
{
    m_unknown_certificates.insert(truncate(id));
}

void DefaultSignHeaderPolicy::request_certificate()
{
    m_cert_requested = true;
}

void DefaultSignHeaderPolicy::request_certificate_chain()
{
    m_chain_requested = true;
}

DefaultSignHeaderPolicyV3::DefaultSignHeaderPolicyV3(const Runtime& rt, PositionProvider& positioning) :
    m_runtime(rt), m_positioning(positioning), m_cam_next_certificate(m_runtime.now()), m_cert_requested(false), m_chain_requested(false)
{
}

std::list<HeaderField> DefaultSignHeaderPolicyV3::prepare_header(const SignRequest& request, CertificateProvider& certificate_provider)
{
    std::list<HeaderField> header_fields;
    return header_fields;
}

void DefaultSignHeaderPolicyV3::prepare_headers(const SignRequest& request, CertificateProviderV3& certificate_provider, SecuredMessageV3& secured_message){
    secured_message.set_generation_time(convert_time64(m_runtime.now()));
    secured_message.set_psid(request.its_aid);

    if (request.its_aid == aid::CA) {
        // section 7.1.1 in TS 103 097 v1.3.1
        SignerInfoV3 signer_info = std::nullptr_t();
        if (m_chain_requested) {
            std::list<CertificateV3> full_chain;
            full_chain.splice(full_chain.end(), certificate_provider.own_chain());
            full_chain.push_back(certificate_provider.own_certificate());
            // Has to be reversed because the following lines from the standard (IEEE 1609.2):
            /* The structure contains one or more Certificate structures, in order
             * such that the first certificate is the authorization certificate and each
             * subsequent certificate is the issuer of the one before it. */
            full_chain.reverse();
            signer_info = full_chain;
            
            m_cam_next_certificate = m_runtime.now() + std::chrono::seconds(1);
        } else if (m_runtime.now() < m_cam_next_certificate && !m_cert_requested) {
            signer_info = certificate_provider.own_certificate().calculate_hash();
        } else {
            signer_info = certificate_provider.own_certificate();
            m_cam_next_certificate = m_runtime.now() + std::chrono::seconds(1);
        }
        secured_message.set_signer_info(signer_info);
        if (m_unknown_certificates.size() > 0) {
            std::list<HashedId3> unknown_certificates(m_unknown_certificates.begin(), m_unknown_certificates.end());
            secured_message.set_inline_p2pcd_request(unknown_certificates);
            
            m_unknown_certificates.clear();
        }
        m_cert_requested = false;
        m_chain_requested = false;
    } else {
        auto position = m_positioning.position_fix();
        if (position.altitude) {
            secured_message.set_generation_location(ThreeDLocation(position.latitude, position.longitude, to_elevation(position.altitude->value())));
        } else {
            secured_message.set_generation_location(ThreeDLocation(position.latitude, position.longitude));
        }
    }

}

void DefaultSignHeaderPolicyV3::request_unrecognized_certificate(HashedId8 id)
{
    m_unknown_certificates.insert(truncate(id));
}

void DefaultSignHeaderPolicyV3::request_certificate()
{
    m_cert_requested = true;
}

void DefaultSignHeaderPolicyV3::request_certificate_chain()
{
    m_chain_requested = true;
}


} // namespace security
} // namespace vanetza
