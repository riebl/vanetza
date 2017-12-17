#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/sign_service.hpp>
#include <cassert>
#include <future>

namespace vanetza
{
namespace security
{
namespace
{

/**
 * \brief signature used as placeholder until final signature is calculated
 * \return placeholder containing dummy data
 */
Signature signature_placeholder()
{
    const auto size = field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256);
    EcdsaSignature ecdsa;
    ecdsa.s.resize(size, 0x00);
    X_Coordinate_Only coordinate;
    coordinate.x.resize(size, 0x00);
    ecdsa.R = std::move(coordinate);
    return Signature { std::move(ecdsa) };
}

} // namespace


SignHeaderPolicy::SignHeaderPolicy(const Clock::time_point& time_now) :
    m_time_now(time_now), m_cam_next_certificate(time_now), m_cert_requested(false), m_chain_requested(false) { }

std::list<HeaderField> SignHeaderPolicy::prepare_header(const SignRequest& request, CertificateProvider& certificate_provider)
{
    std::list<HeaderField> header_fields;

    header_fields.push_back(convert_time64(m_time_now));
    header_fields.push_back(request.its_aid);

    if (request.its_aid == itsAidCa) {
        // section 7.1 in TS 103 097 v1.2.1
        if (m_chain_requested) {
            std::list<Certificate> full_chain;
            full_chain.push_back(certificate_provider.own_certificate());
            for (auto chain_cert : certificate_provider.own_chain()) {
                full_chain.push_back(chain_cert);
            }
            header_fields.push_back(SignerInfo { full_chain });
            m_cam_next_certificate = m_time_now + std::chrono::seconds(1);
        } else if (m_time_now < m_cam_next_certificate && !m_cert_requested) {
            header_fields.push_back(SignerInfo { calculate_hash(certificate_provider.own_certificate()) });
        } else {
            header_fields.push_back(SignerInfo { certificate_provider.own_certificate() });
            m_cam_next_certificate = m_time_now + std::chrono::seconds(1);
        }

        if (m_unknown_certificates.size() > 0) {
            std::list<HashedId3> unknown_certificates;
            unknown_certificates.splice(unknown_certificates.end(), m_unknown_certificates);
            header_fields.push_back(unknown_certificates);
        }

        m_cert_requested = false;
        m_chain_requested = false;
    } else {
        // TODO: Add generation location
        header_fields.push_back(SignerInfo { certificate_provider.own_certificate() });
    }

    return header_fields;
}

void SignHeaderPolicy::report_unknown_certificate(HashedId8 id)
{
    m_unknown_certificates.push_back(truncate(id));
}

void SignHeaderPolicy::report_requested_certificate()
{
    m_cert_requested = true;
}

void SignHeaderPolicy::report_requested_certificate_chain()
{
    m_chain_requested = true;
}

SignService straight_sign_service(CertificateProvider& certificate_provider, Backend& backend, SignHeaderPolicy& sign_header_policy)
{
    return [&](SignRequest&& request) -> SignConfirm {
        SignConfirm confirm;
        confirm.secured_message.payload.type = PayloadType::Signed;
        confirm.secured_message.payload.data = std::move(request.plain_message);

        std::list<HeaderField> header_fields = sign_header_policy.prepare_header(request, certificate_provider);
        for (auto& header_field : header_fields) {
            confirm.secured_message.header_fields.push_back(header_field);
        }

        const auto& private_key = certificate_provider.own_private_key();
        static const Signature placeholder = signature_placeholder();
        static const size_t trailer_size = get_size(TrailerField { placeholder });

        ByteBuffer data_buffer = convert_for_signing(confirm.secured_message, trailer_size);
        TrailerField trailer_field = backend.sign_data(private_key, data_buffer);
        assert(get_size(trailer_field) == trailer_size);
        confirm.secured_message.trailer_fields.push_back(trailer_field);
        return confirm;
    };
}

SignService deferred_sign_service(CertificateProvider& certificate_provider, Backend& backend, SignHeaderPolicy& sign_header_policy)
{
    return [&](SignRequest&& request) -> SignConfirm {
        SignConfirm confirm;
        confirm.secured_message.payload.type = PayloadType::Signed;
        confirm.secured_message.payload.data = std::move(request.plain_message);

        std::list<HeaderField> header_fields = sign_header_policy.prepare_header(request, certificate_provider);
        for (auto& header_field : header_fields) {
            confirm.secured_message.header_fields.push_back(header_field);
        }

        const auto& private_key = certificate_provider.own_private_key();
        static const Signature placeholder = signature_placeholder();
        static const size_t signature_size = get_size(placeholder);
        static const size_t trailer_size = get_size(TrailerField { placeholder });

        const SecuredMessage& secured_message = confirm.secured_message;
        auto future = std::async(std::launch::deferred, [&backend, secured_message, private_key]() {
            ByteBuffer data = convert_for_signing(secured_message, trailer_size);
            return backend.sign_data(private_key, data);
        });
        EcdsaSignatureFuture signature(future.share(), signature_size);
        confirm.secured_message.trailer_fields.push_back(signature);
        return confirm;
    };
}

SignService dummy_sign_service(const Runtime& rt, const SignerInfo& signer_info)
{
    return [&rt, signer_info](SignRequest&& request) -> SignConfirm {
        static const Signature null_signature = signature_placeholder();
        SignConfirm confirm;
        confirm.secured_message.payload.type = PayloadType::Signed;
        confirm.secured_message.payload.data = std::move(request.plain_message);
        confirm.secured_message.header_fields.push_back(convert_time64(rt.now()));
        confirm.secured_message.header_fields.push_back(request.its_aid);
        confirm.secured_message.header_fields.push_back(signer_info);
        confirm.secured_message.trailer_fields.push_back(null_signature);
        return confirm;
    };
}

} // namespace security
} // namespace vanetza
