#include <vanetza/common/its_aid.hpp>
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
    m_time_now(time_now), m_cam_next_certificate(time_now), m_cert_requested(false), m_chain_requested(false)
{
}

std::list<HeaderField> SignHeaderPolicy::prepare_header(const SignRequest& request, CertificateProvider& certificate_provider)
{
    std::list<HeaderField> header_fields;

    header_fields.push_back(convert_time64(m_time_now));
    header_fields.push_back(request.its_aid);

    if (request.its_aid == aid::CA) {
        // section 7.1 in TS 103 097 v1.2.1
        if (m_chain_requested) {
            std::list<Certificate> full_chain;
            full_chain.push_back(certificate_provider.own_certificate());
            full_chain.splice(full_chain.end(), certificate_provider.own_chain());
            header_fields.push_back(SignerInfo { std::move(full_chain) });
            m_cam_next_certificate = m_time_now + std::chrono::seconds(1);
        } else if (m_time_now < m_cam_next_certificate && !m_cert_requested) {
            header_fields.push_back(SignerInfo { calculate_hash(certificate_provider.own_certificate()) });
        } else {
            header_fields.push_back(SignerInfo { certificate_provider.own_certificate() });
            m_cam_next_certificate = m_time_now + std::chrono::seconds(1);
        }

        if (m_unknown_certificates.size() > 0) {
            std::list<HashedId3> unknown_certificates(m_unknown_certificates.begin(), m_unknown_certificates.end());
            header_fields.push_back(unknown_certificates);
            m_unknown_certificates.clear();
        }

        m_cert_requested = false;
        m_chain_requested = false;
    } else {
        // TODO: Add generation location
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
        }

        // all other fields must be encoded in ascending order
        using enum_int = std::underlying_type<HeaderFieldType>::type;
        return static_cast<enum_int>(type_a) < static_cast<enum_int>(type_b);
    });

    return header_fields;
}

void SignHeaderPolicy::report_unknown_certificate(HashedId8 id)
{
    m_unknown_certificates.insert(truncate(id));
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
        confirm.secured_message.header_fields = sign_header_policy.prepare_header(request, certificate_provider);

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
        confirm.secured_message.header_fields = sign_header_policy.prepare_header(request, certificate_provider);

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
