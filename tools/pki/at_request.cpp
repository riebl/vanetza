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
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/InnerAtRequest.h>
#include <vanetza/asn1/security/SharedAtRequest.h>
#include <vanetza/asn1/security/ValidityPeriod.h>
#include <vanetza/common/its_aid.hpp>
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

// Encrypt `plaintext` to `recipient_certificate` using a fresh ECIES context
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
    auto ecies = security.create_ecies_context(*enc_key, recipient_hash);

    EncryptedData::init(dest);
    EncryptedData::set_aes_ccm_ciphertext(dest, *ecies, plaintext);
    EncryptedData::append_recipient_info(dest, *ecies, recipient_certificate.calculate_hashed_id8(security));
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
    ByteBuffer hmac_key = security.generate_nonce(32);
    OCTET_STRING_fromBuf(&iar.hmacKey, reinterpret_cast<const char*>(hmac_key.data()), hmac_key.size());

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
    ByteBuffer verify_oer =
        asn1::encode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &iar.publicKeys.verificationKey);
    ByteBuffer hmac_input = verify_oer;
    if (iar.publicKeys.encryptionKey) {
        ByteBuffer enc_oer =
            asn1::encode_oer(asn_DEF_Vanetza_Security_PublicEncryptionKey, iar.publicKeys.encryptionKey);
        hmac_input.insert(hmac_input.end(), enc_oer.begin(), enc_oer.end());
    }
    ByteBuffer full_tag = security.calculate_hmac_sha256(hmac_key, hmac_input);
    OCTET_STRING_fromBuf(&sar.keyTag, reinterpret_cast<const char*>(full_tag.data()), 16);

    // 5. EC proof: external-payload signed data over SharedAtRequest, signed by EC.
    ByteBuffer sar_encoded = asn1::encode_oer(asn_DEF_Vanetza_Security_SharedAtRequest, &sar);
    SignedData ec_signed =
        create_external_signed(sar_encoded, security, params.ec->get_public_key(), params.hash_algo, params.ec);
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
    SignedData pop_signed = create_signed(mgmt_encoded, security, params.verification_key, params.hash_algo, nullptr);
    return pop_signed.encode();
}

EncryptedData build_authorization_request(SecurityModule& security, const AuthorizationRequestParameters& params)
{
    validate(params);

    ByteBuffer plaintext = build_signed_authorization_request(security, params);

    boost::optional<PublicKey> aa_enc_key = params.aa_certificate->get_encryption_key();
    if (!aa_enc_key) {
        throw DecodingFailure("AuthorizationRequest: AA certificate has no encryption key");
    }
    Sha256Hash aa_hash = calculate_sha256_hash(security, *params.aa_certificate);
    auto ecies_unique = security.create_ecies_context(*aa_enc_key, aa_hash);
    std::shared_ptr<SecurityModule::EciesContext> ecies { std::move(ecies_unique) };

    EncryptedData encrypted { ecies };
    encrypted.generate_ciphertext(plaintext);
    encrypted.add_recipient_info(params.aa_certificate->calculate_hashed_id8(security));
    return encrypted;
}

} // namespace pki
} // namespace vanetza
