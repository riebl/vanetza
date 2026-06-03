#include "signed_builder.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "hashed_id8.hpp"
#include "security_module.hpp"
#include "time.hpp"
#include "validation.hpp"
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <stdexcept>

namespace vanetza
{
namespace pki
{

namespace
{

// Map a Signature into the asn1c Vanetza_Security_Signature_t representation.
void copy_signature(const Signature& from, Vanetza_Security_Signature_t& to)
{
    switch (from.type) {
        case KeyType::NistP256:
            to.present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
            to.choice.ecdsaNistP256Signature.rSig.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
            copy_left_padded(from.r, to.choice.ecdsaNistP256Signature.rSig.choice.x_only, 32);
            copy_left_padded(from.s, to.choice.ecdsaNistP256Signature.sSig, 32);
            break;
        case KeyType::BrainpoolP256r1:
            to.present = Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature;
            to.choice.ecdsaBrainpoolP256r1Signature.rSig.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
            copy_left_padded(from.r, to.choice.ecdsaBrainpoolP256r1Signature.rSig.choice.x_only, 32);
            copy_left_padded(from.s, to.choice.ecdsaBrainpoolP256r1Signature.sSig, 32);
            break;
        case KeyType::BrainpoolP384r1:
            to.present = Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature;
            to.choice.ecdsaBrainpoolP384r1Signature.rSig.present = Vanetza_Security_EccP384CurvePoint_PR_x_only;
            copy_left_padded(from.r, to.choice.ecdsaBrainpoolP384r1Signature.rSig.choice.x_only, 48);
            copy_left_padded(from.s, to.choice.ecdsaBrainpoolP384r1Signature.sSig, 48);
            break;
        default:
            throw std::runtime_error("unknown key type");
    }
}

// Build the EtsiTs103097Data-Signed envelope with its inner SignedData skeleton
SignedData init_signed_envelope(SecurityModule& security, HashAlgorithm hash_algo, const Certificate* signer_cert)
{
    SignedData envelope;
    envelope->protocolVersion = ieee1609dot2_protocol_version;
    envelope->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
    envelope->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_signedData;
    envelope->content->choice.signedData = asn1::allocate<Vanetza_Security_SignedData_t>();

    Vanetza_Security_SignedData_t* signed_data = envelope->content->choice.signedData;
    signed_data->hashId = convert(hash_algo);

    if (signer_cert) {
        signed_data->signer.present = Vanetza_Security_SignerIdentifier_PR_digest;
        HashedId8 hid8 = signer_cert->calculate_hashed_id8(security);
        if (OCTET_STRING_fromBuf(&signed_data->signer.choice.digest,
                reinterpret_cast<const char*>(hid8.octets.data()), hid8.octets.size()) != 0) {
            throw std::runtime_error("setting signer digest failed");
        }
    } else {
        signed_data->signer.present = Vanetza_Security_SignerIdentifier_PR_self;
    }

    signed_data->tbsData = asn1::allocate<Vanetza_Security_ToBeSignedData_t>();
    signed_data->tbsData->headerInfo.psid = aid::SCR;
    signed_data->tbsData->headerInfo.generationTime = asn1::allocate<Vanetza_Security_Time64_t>();
    if (asn_uint642INTEGER(signed_data->tbsData->headerInfo.generationTime,
            security::v3::convert_time64(current_time())) != 0) {
        throw std::runtime_error("setting generationTime failed");
    }

    signed_data->tbsData->payload = asn1::allocate<Vanetza_Security_SignedDataPayload_t>();
    return envelope;
}

// Sign the tbsData (already populated by the caller) and copy the resulting
// signature into signed_data->signature.
void sign_and_finalize(Vanetza_Security_SignedData_t* signed_data, SecurityModule& security,
    const PublicKey& signing_key, HashAlgorithm hash_algo, const Certificate* signer_cert)
{
    const Vanetza_Security_Certificate_t* raw_cert = signer_cert ? &signer_cert->raw() : nullptr;
    ByteBuffer sign_input;
    switch (hash_algo) {
        case HashAlgorithm::SHA256: {
            Sha256Hash d = calculate_digest<Sha256Hash>(security, *signed_data->tbsData, raw_cert);
            sign_input.assign(d.octets.begin(), d.octets.end());
            break;
        }
        case HashAlgorithm::SHA384: {
            Sha384Hash d = calculate_digest<Sha384Hash>(security, *signed_data->tbsData, raw_cert);
            sign_input.assign(d.octets.begin(), d.octets.end());
            break;
        }
        default:
            throw std::runtime_error("unknown hash algorithm");
    }

    boost::optional<Signature> signature = security.sign(sign_input, signing_key);
    if (!signature) {
        throw std::runtime_error("signing failed: private key unknown to security module");
    }
    copy_signature(*signature, signed_data->signature);
}

} // namespace

SignedData create_signed(const ByteBuffer& payload, SecurityModule& security,
    const PublicKey& signing_key, HashAlgorithm hash_algo, const Certificate* signer_cert)
{
    SignedData envelope = init_signed_envelope(security, hash_algo, signer_cert);
    Vanetza_Security_SignedData_t* signed_data = envelope->content->choice.signedData;

    auto* sdp = signed_data->tbsData->payload;
    sdp->data = asn1::allocate<Vanetza_Security_EtsiTs103097Data_t>();
    sdp->data->protocolVersion = ieee1609dot2_protocol_version;
    sdp->data->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
    sdp->data->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData;
    copy(payload, sdp->data->content->choice.unsecuredData);

    sign_and_finalize(signed_data, security, signing_key, hash_algo, signer_cert);
    return envelope;
}

SignedData create_external_signed(const ByteBuffer& external_payload, SecurityModule& security,
    const PublicKey& signing_key, HashAlgorithm hash_algo, const Certificate* signer_cert)
{
    // The asn1c HashedData CHOICE only carries sha256HashedData; SHA-384
    // would need a newer 1609.2 schema. SharedAtRequest in TS 102 941
    // is hashed with SHA-256 in practice, so this restriction is fine.
    if (hash_algo != HashAlgorithm::SHA256) {
        throw std::invalid_argument("create_external_signed: only SHA-256 is supported for extDataHash");
    }

    SignedData envelope = init_signed_envelope(security, hash_algo, signer_cert);
    Vanetza_Security_SignedData_t* signed_data = envelope->content->choice.signedData;

    auto* sdp = signed_data->tbsData->payload;
    sdp->extDataHash = asn1::allocate<Vanetza_Security_HashedData_t>();
    Sha256Hash h = security.calculate_sha256_hash(external_payload.data(), external_payload.size());
    sdp->extDataHash->present = Vanetza_Security_HashedData_PR_sha256HashedData;
    if (OCTET_STRING_fromBuf(&sdp->extDataHash->choice.sha256HashedData,
            reinterpret_cast<const char*>(h.octets.data()), h.octets.size()) != 0) {
        throw std::runtime_error("setting extDataHash failed");
    }

    sign_and_finalize(signed_data, security, signing_key, hash_algo, signer_cert);
    return envelope;
}

} // namespace pki
} // namespace vanetza
