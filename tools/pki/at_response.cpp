#include "at_response.hpp"
#include "asn1.hpp"
#include "exception.hpp"
#include "hashed_id8.hpp"
#include "security_module.hpp"
#include "signed_data.hpp"
#include "validation.hpp"
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/InnerAtResponse.h>
#include <vanetza/common/its_aid.hpp>

namespace vanetza
{
namespace pki
{

AuthorizationResponse parse_authorization_response(SecurityModule& security, const ByteBuffer& decrypted,
    const Certificate& aa_certificate)
{
    SignedData outer;
    if (!outer.decode(decrypted)) {
        throw DecodingFailure("decoding signed authorization response failed");
    }
    if (outer->content->present != Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        throw DecodingFailure("authorization response content is not signedData");
    }
    const Vanetza_Security_SignedData_t& sd = *outer->content->choice.signedData;

    // Per TS 102 941 §6.2.3.3.2 the AA signs with signer = digest(AA cert).
    const HashedId8 aa_hid8 = aa_certificate.calculate_hashed_id8(security);
    if (sd.signer.present != Vanetza_Security_SignerIdentifier_PR_digest) {
        throw DecodingFailure("authorization response must have signer = digest");
    }
    if (sd.signer.choice.digest != aa_hid8.octets) {
        throw VerificationFailure("authorization response signer digest does not match AA certificate");
    }

    if (sd.tbsData->headerInfo.psid != aid::SCR) {
        throw DecodingFailure("authorization response PSID is not SCR");
    }

    if (!validate(security, sd, aa_certificate.raw())) {
        throw VerificationFailure("authorization response signature does not verify against AA certificate");
    }

    const Vanetza_Security_Opaque_t* inner_opaque = get_signed_payload(outer->content);
    if (!inner_opaque) {
        throw DecodingFailure("authorization response carries no unsecured signed payload");
    }

    AuthorizationResponseData inner = AuthorizationResponseData::from_opaque(*inner_opaque);
    if (inner->version != Vanetza_Security_Version_v1) {
        throw DecodingFailure("inner EtsiTs102941Data version is not v1");
    }

    const Vanetza_Security_InnerAtResponse_t& at_resp = inner->content.choice.authorizationResponse;

    AuthorizationResponse result;
    result.code = AuthorizationResponseCode { at_resp.responseCode };
    result.request_hash.assign(at_resp.requestHash.buf, at_resp.requestHash.buf + at_resp.requestHash.size);

    if (at_resp.certificate) {
        result.certificate = Certificate(*at_resp.certificate);
    }

    if (at_resp.responseCode == Vanetza_Security_AuthorizationResponseCode_ok && !result.certificate) {
        throw DecodingFailure("authorization response code is ok but no certificate is included");
    }

    return result;
}

} // namespace pki
} // namespace vanetza
