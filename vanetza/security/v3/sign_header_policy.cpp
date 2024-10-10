#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_provider.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

DefaultSignHeaderPolicy::DefaultSignHeaderPolicy(const Runtime& rt, PositionProvider& positioning, CertificateProvider& certs) :
    m_runtime(rt), m_positioning(positioning), m_cert_provider(certs),
    m_cam_next_certificate(m_runtime.now()),
    m_cert_requested(false)
{
}

void DefaultSignHeaderPolicy::prepare_header(const SignRequest& request, SecuredMessage& secured_message)
{
    const auto now = m_runtime.now();
    secured_message.set_its_aid(request.its_aid);
    secured_message.set_generation_time(vanetza::security::v2::convert_time64(now));

    if (request.its_aid == aid::CA) {
        bool signer_full_cert = false;
        const auto& at_cert = m_cert_provider.own_certificate();
        const auto maybe_at_digest = at_cert.calculate_digest();

        // include full certificate if its digest has been requested by a peer
        if (maybe_at_digest && m_incoming_requests.is_pending(truncate(*maybe_at_digest))) {
            m_cert_requested = true;
            m_incoming_requests.discard_request(truncate(*maybe_at_digest));
        }

        // section 7.1.1 in TS 103 097 v2.1.1
        if (now < m_cam_next_certificate && !m_cert_requested) {
            if (maybe_at_digest) {
                secured_message.set_signer_identifier(*maybe_at_digest);
            }
        } else {
            signer_full_cert = true;
            m_cert_requested = false;
            secured_message.set_signer_identifier(at_cert);
            m_cam_next_certificate = now + std::chrono::seconds(1) - std::chrono::milliseconds(50);
        }

        // peer-to-peer certificate distribution
        secured_message.set_inline_p2pcd_request(m_outgoing_requests.all());
        while (auto p2p_hid = m_incoming_requests.next_one()) {
            // provide requested CA certificates (no AT certificates here)
            auto p2p_cert = m_cert_provider.cache().lookup(*p2p_hid);
            if (p2p_cert && p2p_cert->is_ca_certificate()) {
                secured_message.set_requested_certificate(*p2p_cert);
                break;
            }
        }
    } else if (request.its_aid == aid::DEN) {
        // section 7.1.2 in TS 103 097 v2.1.1
        secured_message.set_signer_identifier(m_cert_provider.own_certificate());
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
    } else {
        secured_message.set_signer_identifier(m_cert_provider.own_certificate());
    }
}

void DefaultSignHeaderPolicy::request_unrecognized_certificate(HashedId8 id)
{
    m_outgoing_requests.add_request(truncate(id));
}

void DefaultSignHeaderPolicy::request_certificate()
{
    m_cert_requested = true;
}

void DefaultSignHeaderPolicy::enqueue_p2p_request(HashedId3 id)
{
    m_incoming_requests.add_request(id);
}

void DefaultSignHeaderPolicy::discard_p2p_request(HashedId3 id)
{
    m_incoming_requests.discard_request(id);
}

} // namespace v3
} // namespace security
} // namespace vanetza
