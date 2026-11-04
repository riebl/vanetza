#include "at_request.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "encrypted_data.hpp"
#include "exception.hpp"
#include "hashed_id8.hpp"
#include "psid_ssp.hpp"
#include "security_module.hpp"
#include "sha.hpp"
#include "signed_builder.hpp"
#include <vanetza/asn1/byte_view.hpp>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/InnerAtRequest.h>
#include <vanetza/asn1/security/SharedAtRequest.h>
#include <vanetza/asn1/security/ValidityPeriod.h>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/hmac.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <memory>
#include <stdexcept>

namespace vanetza
{
namespace pki
{

namespace
{

void add_app_permissions(Vanetza_Security_CertificateSubjectAttributes_t& csa, const std::list<PsidSsp>& permissions)
{
    csa.appPermissions = asn1::allocate<Vanetza_Security_SequenceOfPsidSsp_t>();
    for (const auto& perm : permissions) {
        auto* psid_ssp = asn1::allocate<Vanetza_Security_PsidSsp_t>();
        psid_ssp->psid = perm.psid;
        if (!perm.ssp.empty()) {
            psid_ssp->ssp = asn1::allocate<Vanetza_Security_ServiceSpecificPermissions_t>();
            psid_ssp->ssp->present = Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp;
            copy(perm.ssp, psid_ssp->ssp->choice.bitmapSsp);
        }
        if (asn_sequence_add(csa.appPermissions, psid_ssp) != 0) {
            throw std::runtime_error("adding app permission to InnerAtRequest failed");
        }
    }
}

// Encrypt `plaintext` to `recipient_certificate` using a fresh AES key
// and populate `dest` (an EtsiTs103097Data-Encrypted value member of a parent
// struct) in place. Precondition: `dest` is zero-initialised.
void encrypt_into(Vanetza_Security_EtsiTs103097Data_Encrypted_85P0_t& dest, SecurityModule& security,
    const ByteBuffer& plaintext, const Certificate& recipient_certificate)
{
    boost::optional<PublicKey> enc_key = recipient_certificate.get_encryption_key();
    if (!enc_key) {
        throw DecodingFailure("recipient certificate has no encryption key");
    }
    Sha256Hash recipient_hash = calculate_sha256_hash(security, recipient_certificate);
    expected<security::Aes128Key> key = security.generate_aes_key();
    if (!key) {
        throw std::runtime_error("AES key generation failed: " + key.error().message());
    }
    expected<EncryptedSymmetricKey> encrypted_key = security.encrypt_key(*enc_key, *key, recipient_hash);
    if (!encrypted_key) {
        throw std::runtime_error("key encryption failed: " + encrypted_key.error().message());
    }

    EncryptedData::init(dest);
    EncryptedData::set_aes_ccm_ciphertext(dest, security, *key, plaintext);
    EncryptedData::append_recipient_info(dest, *encrypted_key, recipient_certificate.calculate_hashed_id8(security));
}

void validate(const AuthorizationRequestParameters& p)
{
    if (!p.ec) {
        throw std::invalid_argument("AuthorizationRequest: ec is required");
    }
    if (!p.ea_certificate) {
        throw std::invalid_argument("AuthorizationRequest: ea_certificate is required");
    }
    if (!p.aa_certificate) {
        throw std::invalid_argument("AuthorizationRequest: aa_certificate is required");
    }
    if (p.permissions.empty()) {
        throw std::invalid_argument("AuthorizationRequest: at least one permission must be requested");
    }
    if (p.hash_algo != HashAlgorithm::SHA256) {
        throw std::invalid_argument("AuthorizationRequest: only SHA-256 is supported");
    }
}

} // namespace

ByteBuffer build_signed_authorization_request(SecurityModule& security, const AuthorizationRequestParameters& params)
{
    validate(params);

    // Outer EtsiTs102941Data{authorizationRequest = InnerAtRequest}.
    // We populate the InnerAtRequest fields in place inside the wrapper.
    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    mgmt->version = Vanetza_Security_Version_v1;
    mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_authorizationRequest;
    Vanetza_Security_InnerAtRequest_t& iar = mgmt->content.choice.authorizationRequest;

    // 1. Public keys carried in the request
    // verificationKey is required and will be the new AT's verification key
    set_verification_key(iar.publicKeys.verificationKey, params.verification_key);
    // encryptionKey is optional for future encrypted communication
    if (params.at_encryption_key) {
        iar.publicKeys.encryptionKey = asn1::allocate<Vanetza_Security_PublicEncryptionKey_t>();
        set_encryption_key(*iar.publicKeys.encryptionKey, *params.at_encryption_key);
    }

    // 2. Random 32-byte hmacKey
    expected<security::HmacKey> hmac_key = security.generate_hmac_key();
    if (!hmac_key) {
        throw std::runtime_error("HMAC key generation failed: " + hmac_key.error().message());
    }
    auto hmac_key_view = create_byte_view(hmac_key->octets);
    asn1::assign(iar.hmacKey, hmac_key_view);

    // 3. SharedAtRequest
    Vanetza_Security_SharedAtRequest_t& sar = iar.sharedAtRequest;
    HashedId8 ea_hid8 = params.ea_certificate->calculate_hashed_id8(security);
    OCTET_STRING_fromBuf(&sar.eaId, reinterpret_cast<const char*>(ea_hid8.octets.data()), ea_hid8.octets.size());
    sar.certificateFormat = Vanetza_Security_CertificateFormat_ts103097v131;
    add_app_permissions(sar.requestedSubjectAttributes, params.permissions);
    if (params.validity_period) {
        sar.requestedSubjectAttributes.validityPeriod = asn1::allocate<Vanetza_Security_ValidityPeriod_t>();
        auto* vp = sar.requestedSubjectAttributes.validityPeriod;
        vp->start = security::v3::convert_time32(params.validity_period->start);
        vp->duration.present = Vanetza_Security_Duration_PR_hours;
        vp->duration.choice.hours = params.validity_period->duration.count();
    }

    // 4. keyTag = first 16 bytes of HMAC-SHA256(hmacKey, verifyKey [|| encKey])
    ByteBuffer hmac_input =
        asn1::encode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &iar.publicKeys.verificationKey);
    if (iar.publicKeys.encryptionKey) {
        ByteBuffer enc_oer =
            asn1::encode_oer(asn_DEF_Vanetza_Security_PublicEncryptionKey, iar.publicKeys.encryptionKey);
        hmac_input.insert(hmac_input.end(), enc_oer.begin(), enc_oer.end());
    }
    expected<security::Sha256Hmac> hmac = security.calculate_hmac_sha256(hmac_key_view, create_byte_view(hmac_input));
    if (!hmac) {
        throw std::runtime_error("HMAC calculation failed: " + hmac.error().message());
    }
    const security::KeyTag key_tag(*hmac);
    asn1::assign(sar.keyTag, create_byte_view(key_tag.octets));

    // 5. EC proof: external-payload signed data over SharedAtRequest, signed by EC.
    ByteBuffer sar_encoded = asn1::encode_oer(asn_DEF_Vanetza_Security_SharedAtRequest, &sar);
    SignedData ec_signed =
        create_external_signed(sar_encoded, security, params.ec_key, params.hash_algo, params.ec);
    ByteBuffer ec_signed_encoded = ec_signed.encode();

    // 6. Encrypt the EC proof to the EA → encryptedEcSignature
    iar.ecSignature.present = Vanetza_Security_EcSignature_PR_encryptedEcSignature;
    encrypt_into(iar.ecSignature.choice.encryptedEcSignature, security, ec_signed_encoded, *params.ea_certificate);

    if (!mgmt.validate()) {
        throw std::runtime_error("AuthorizationRequest: constructed InnerAtRequest is invalid");
    }
    ByteBuffer mgmt_encoded = mgmt.encode();

    if (!params.include_pop) {
        return mgmt_encoded;
    }

    // 7. POP wrap: EtsiTs103097Data-Signed (signer = self) signed with the new AT verification key
    SignedData pop_signed = create_signed(mgmt_encoded, security, params.pop_signer_key, params.hash_algo, nullptr);
    return pop_signed.encode();
}

EncryptedRequest build_authorization_request(SecurityModule& security, const AuthorizationRequestParameters& params)
{
    validate(params);

    ByteBuffer plaintext = build_signed_authorization_request(security, params);

    boost::optional<PublicKey> aa_enc_key = params.aa_certificate->get_encryption_key();
    if (!aa_enc_key) {
        throw DecodingFailure("AuthorizationRequest: AA certificate has no encryption key");
    }
    Sha256Hash aa_hash = calculate_sha256_hash(security, *params.aa_certificate);
    expected<security::Aes128Key> key = security.generate_aes_key();
    if (!key) {
        throw std::runtime_error("AES key generation failed: " + key.error().message());
    }
    expected<EncryptedSymmetricKey> encrypted_key = security.encrypt_key(*aa_enc_key, *key, aa_hash);
    if (!encrypted_key) {
        throw std::runtime_error("key encryption failed: " + encrypted_key.error().message());
    }

    EncryptedRequest request { EncryptedData {}, *key };
    request.message.generate_ciphertext(security, request.key, plaintext);
    request.message.add_recipient_info(params.aa_certificate->calculate_hashed_id8(security), *encrypted_key);
    return request;
}

} // namespace pki
} // namespace vanetza
