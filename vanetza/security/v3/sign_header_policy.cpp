#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_provider.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <list>

namespace vanetza
{
namespace security
{
namespace v3
{

DefaultSignHeaderPolicy::DefaultSignHeaderPolicy(const Runtime& rt, PositionProvider& positioning) :
    m_runtime(rt), m_positioning(positioning), m_cam_next_certificate(m_runtime.now()), m_cert_requested(false), m_chain_requested(false)
{
}

void DefaultSignHeaderPolicy::prepare_header(const SignRequest& request, CertificateProvider& certificate_provider, SecuredMessage& secured_message)
{
    const auto now = m_runtime.now();
    secured_message.set_its_aid(request.its_aid);
    secured_message.set_generation_time(vanetza::security::v2::convert_time64(now));
    //header_info.signer_info = certificate_provider.own_certificate();

    if (request.its_aid == aid::CA) {
        // section 7.1.1 in TS 103 097 v2.1.1
        if (now < m_cam_next_certificate && !m_cert_requested) {
            auto maybe_digest = calculate_digest(*certificate_provider.own_certificate());
            if (maybe_digest) {
                secured_message.set_signer_identifier(*maybe_digest);
            }
        } else {
            secured_message.set_signer_identifier(certificate_provider.own_certificate());
            m_cam_next_certificate = now + std::chrono::seconds(1) - std::chrono::milliseconds(50);
        }

        if (m_unknown_certificates.size() > 0) {
            std::list<HashedId3> unknown_certificates(m_unknown_certificates.begin(), m_unknown_certificates.end());
            secured_message.set_inline_p2pcd_request(unknown_certificates);
            m_unknown_certificates.clear();
        }
        m_cert_requested = false;
        m_chain_requested = false;
    }
    else if (request.its_aid == aid::DEN) {
        // section 7.1.2 in TS 103 097 v2.1.1
        secured_message.set_signer_identifier(certificate_provider.own_certificate());
        asn1::ThreeDLocation location;
        v2::ThreeDLocation location_v2;
        auto position = m_positioning.position_fix();
        if (position.altitude) {
            location_v2 = v2::ThreeDLocation(position.latitude, position.longitude, v2::to_elevation(position.altitude->value()));
        } else {
            location_v2 = v2::ThreeDLocation(position.latitude, position.longitude);
        }
        location.latitude = location_v2.latitude.value();
        location.longitude = location_v2.longitude.value();
        location.elevation = 0;
        secured_message.set_generation_location(location);
    }
    else {
        secured_message.set_signer_identifier(certificate_provider.own_certificate());
    }
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

} // namespace v3
} // namespace security
} // namespace vanetza
