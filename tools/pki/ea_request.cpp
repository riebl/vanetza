#include "ea_request.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "encrypted_data.hpp"
#include "exception.hpp"
#include "psid_ssp.hpp"
#include "security_module.hpp"
#include "signed_builder.hpp"
#include "signed_data.hpp"
#include <vanetza/asn1/security/InnerEcRequest.h>
#include <vanetza/common/its_aid.hpp>
#include <stdexcept>

namespace vanetza
{
namespace pki
{

namespace
{

class InnerEcRequest : public asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest_t>
{
public:
    using wrapper = asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest_t>;

    InnerEcRequest() : wrapper(asn_DEF_Vanetza_Security_InnerEcRequest)
    {
        m_struct->certificateFormat = Vanetza_Security_CertificateFormat_ts103097v131;
    }

    void set_its_id(const std::string& id)
    {
        if (OCTET_STRING_fromBuf(&m_struct->itsId, id.data(), id.size()) != 0) {
            throw std::runtime_error("setting ITS ID failed");
        }
    }

    void set_verification_key(const PublicKey& pubkey)
    {
        pki::set_verification_key(m_struct->publicKeys.verificationKey, pubkey);
    }

    void add_permission(const PsidSsp& perm)
    {
        if (m_struct->requestedSubjectAttributes.appPermissions == nullptr) {
            m_struct->requestedSubjectAttributes.appPermissions =
                asn1::allocate<Vanetza_Security_SequenceOfPsidSsp_t>();
        }

        auto psid_ssp = asn1::allocate<Vanetza_Security_PsidSsp_t>();
        psid_ssp->psid = perm.psid;
        if (!perm.ssp.empty()) {
            psid_ssp->ssp = asn1::allocate<Vanetza_Security_ServiceSpecificPermissions_t>();
            psid_ssp->ssp->present = Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp;
            copy(perm.ssp, psid_ssp->ssp->choice.bitmapSsp);
        }

        auto* perms = m_struct->requestedSubjectAttributes.appPermissions;
        if (asn_sequence_add(perms, psid_ssp) != 0) {
            throw std::runtime_error("adding app permission to InnerEcRequest failed");
        }
    }
};

} // namespace

ByteBuffer build_signed_enrolment_request(
    SecurityModule& security, CryptoProvider& crypto, const EnrolmentRequestParameters& params)
{
    if (params.its_id.empty()) {
        throw std::invalid_argument("EnrolmentRequest: its_id must not be empty");
    }

    // 1. InnerEcRequest
    InnerEcRequest inner;
    inner.set_its_id(params.its_id);
    inner.set_verification_key(params.verification_key);
    inner.add_permission(PsidSsp { aid::SCR, { 0x01, 0xC0 } });
    if (!inner.validate()) {
        throw std::runtime_error("EnrolmentRequest: constructed InnerEcRequest is invalid");
    }

    // 2. InnerEcRequestSignedForPop wrapped in EtsiTs102941Data
    MgmtData pop_data;
    pop_data->version = Vanetza_Security_Version_v1;
    pop_data->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentRequest;
    // Inner PoP is always signer = self (TS 102 941 §6.2.3.2.1)
    create_signed(inner.encode(), security, crypto, params.pop_signer_key, params.hash_algo, nullptr)
        .move_into(pop_data->content.choice.enrolmentRequest);

    // 3. Outer EtsiTs103097Data-Signed: signer = self for initial enrolment or
    //    signer = digest(outer_signer_certificate) for a re-keying renewal.
    SignedData outer = create_signed(pop_data.encode(), security, crypto, params.outer_signer_key, params.hash_algo,
        params.outer_signer_certificate);
    return outer.encode();
}

EncryptedRequest build_enrolment_request(SecurityModule& security, CryptoProvider& crypto,
    const EnrolmentRequestParameters& params, const Certificate& ea_certificate)
{
    boost::optional<PublicKey> ea_enckey = ea_certificate.get_encryption_key();
    if (!ea_enckey) {
        throw DecodingFailure("EnrolmentRequest: EA certificate has no encryption key");
    }

    ByteBuffer signed_request = build_signed_enrolment_request(security, crypto, params);

    Sha256Hash ea_cert_sha256 = calculate_sha256_hash(crypto, ea_certificate);
    expected<security::Aes128Key> key = security.generate_aes_key();
    if (!key) {
        throw std::runtime_error("AES key generation failed: " + key.error().message());
    }
    expected<EncryptedSymmetricKey> encrypted_key = security.encrypt_key(*ea_enckey, *key, ea_cert_sha256);
    if (!encrypted_key) {
        throw std::runtime_error("key encryption failed: " + encrypted_key.error().message());
    }
    EncryptedRequest request { EncryptedData {}, *key };
    request.message.generate_ciphertext(crypto, request.key, signed_request);
    request.message.add_recipient_info(ea_certificate.calculate_hashed_id8(crypto), *encrypted_key);

    return request;
}

} // namespace pki
} // namespace vanetza
