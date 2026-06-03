#pragma once

#include "asn1.hpp"
#include "certificate.hpp"
#include "keys.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <chrono>
#include <cstdlib>

namespace vanetza
{
namespace pki
{

// Minimal certificate built around a given verification key (and optional
// encryption key). Not TS-compliant (no issuer chain, no permissions, no
// signature) but just enough that get_public_key/get_encryption_key return our
// keys and the cert OER-encodes so calculate_hashed_id8 is stable. Intended
// for unit tests where the cert only needs to act as a key holder + digest
// source.
inline Certificate build_stub_certificate(const PublicKey& verify_key, const PublicKey* encryption_key = nullptr,
    Clock::time_point valid_since = Clock::time_point {}, std::chrono::hours validity = std::chrono::hours(24))
{
    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Certificate_t>
        cert(asn_DEF_Vanetza_Security_EtsiTs103097Certificate);
    cert->version = 3;
    cert->type = Vanetza_Security_CertificateType_explicit;
    cert->issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
    cert->issuer.choice.self = Vanetza_Security_HashAlgorithm_sha256;

    auto& tbs = cert->toBeSigned;
    tbs.id.present = Vanetza_Security_CertificateId_PR_name;
    OCTET_STRING_fromBuf(&tbs.id.choice.name, "test-cert", 9);
    tbs.cracaId.buf = static_cast<uint8_t*>(std::calloc(3, 1));
    tbs.cracaId.size = 3;
    tbs.crlSeries = 0;
    tbs.validityPeriod.start = security::v3::convert_time32(valid_since);
    tbs.validityPeriod.duration.present = Vanetza_Security_Duration_PR_hours;
    tbs.validityPeriod.duration.choice.hours = validity.count();
    tbs.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    set_verification_key(tbs.verifyKeyIndicator.choice.verificationKey, verify_key);

    if (encryption_key) {
        tbs.encryptionKey = asn1::allocate<Vanetza_Security_PublicEncryptionKey_t>();
        set_encryption_key(*tbs.encryptionKey, *encryption_key);
    }

    Certificate result;
    ByteBuffer encoded = cert.encode();
    result.decode(encoded);
    return result;
}

} // namespace pki
} // namespace vanetza
