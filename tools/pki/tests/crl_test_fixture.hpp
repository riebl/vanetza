#pragma once

#include "asn1.hpp"
#include "certificate_revocation_list.hpp"
#include "hashed_id8.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/EtsiTs103097Data.h>
#include <vanetza/asn1/security/Ieee1609Dot2Content.h>
#include <vanetza/asn1/security/SignedData.h>
#include <vanetza/asn1/security/ToBeSignedCrl.h>
#include <vanetza/common/its_aid.hpp>
#include <array>
#include <stdexcept>
#include <vector>

namespace vanetza
{
namespace pki
{

// Build a CertificateRevocationList carrying \p revoked entries, signed (in
// the SignerIdentifier sense) by the digest \p issuer. The ECDSA signature
// itself is dummy zeros — sufficient for tests that don't verify it.
inline CertificateRevocationList build_test_crl(const HashedId8& issuer, const std::vector<HashedId8>& revoked)
{
    // The signed payload is an EtsiTs102941Data whose content CHOICE carries the
    // ToBeSignedCrl — matching CertificateRevocationList::revoked_entries().
    ByteBuffer tbs_bytes;
    {
        asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
        mgmt->version = 1;
        mgmt->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_certificateRevocationList;
        Vanetza_Security_ToBeSignedCrl_t& tbs = mgmt->content.choice.certificateRevocationList;
        tbs.version = 1;
        tbs.thisUpdate = 0;
        tbs.nextUpdate = 0;
        for (const auto& id : revoked) {
            auto* entry = asn1::allocate<Vanetza_Security_CrlEntry_t>();
            OCTET_STRING_fromBuf(entry, reinterpret_cast<const char*>(id.octets.data()), id.octets.size());
            asn_sequence_add(&tbs.entries, entry);
        }
        tbs_bytes = mgmt.encode();
    }

    asn1::asn1c_oer_wrapper<Vanetza_Security_CertificateRevocationListMessage_t>
        outer(asn_DEF_Vanetza_Security_CertificateRevocationListMessage);
    outer->protocolVersion = 3;
    outer->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
    outer->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_signedData;

    auto* signed_data = asn1::allocate<Vanetza_Security_SignedData_t>();
    outer->content->choice.signedData = signed_data;
    signed_data->hashId = Vanetza_Security_HashAlgorithm_sha256;

    signed_data->signer.present = Vanetza_Security_SignerIdentifier_PR_digest;
    OCTET_STRING_fromBuf(&signed_data->signer.choice.digest, reinterpret_cast<const char*>(issuer.octets.data()),
        issuer.octets.size());

    signed_data->tbsData = asn1::allocate<Vanetza_Security_ToBeSignedData_t>();
    signed_data->tbsData->headerInfo.psid = aid::CRL;
    signed_data->tbsData->payload = asn1::allocate<Vanetza_Security_SignedDataPayload_t>();
    auto* inner = asn1::allocate<Vanetza_Security_EtsiTs103097Data_t>();
    signed_data->tbsData->payload->data = inner;
    inner->protocolVersion = 3;
    inner->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
    inner->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData;
    OCTET_STRING_fromBuf(&inner->content->choice.unsecuredData, reinterpret_cast<const char*>(tbs_bytes.data()),
        tbs_bytes.size());

    signed_data->signature.present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
    signed_data->signature.choice.ecdsaNistP256Signature.rSig.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
    std::array<std::uint8_t, 32> zeros {};
    OCTET_STRING_fromBuf(&signed_data->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only,
        reinterpret_cast<const char*>(zeros.data()), zeros.size());
    OCTET_STRING_fromBuf(&signed_data->signature.choice.ecdsaNistP256Signature.sSig,
        reinterpret_cast<const char*>(zeros.data()), zeros.size());

    ByteBuffer outer_bytes = outer.encode();
    CertificateRevocationList crl;
    if (!crl.decode(outer_bytes)) {
        throw std::runtime_error("test fixture: outer CRL message could not be decoded");
    }
    return crl;
}

inline HashedId8 make_id(std::uint8_t fill)
{
    HashedId8 id;
    id.octets.fill(fill);
    return id;
}

} // namespace pki
} // namespace vanetza
