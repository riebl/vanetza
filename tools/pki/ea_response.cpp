#include "ea_response.hpp"
#include "asn1.hpp"
#include "exception.hpp"
#include "hashed_id8.hpp"
#include "security_module.hpp"
#include "signed_data.hpp"
#include "validation.hpp"
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/InnerEcResponse.h>
#include <vanetza/common/its_aid.hpp>

namespace vanetza
{
namespace pki
{

EnrolmentResponse parse_enrolment_response(SecurityModule& security, const ByteBuffer& decrypted,
    const Certificate& ea_certificate)
{
    SignedData outer;
    if (!outer.decode(decrypted)) {
        throw DecodingFailure("decoding signed enrolment response failed");
    }
    if (outer->content->present != Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        throw DecodingFailure("enrolment response content is not signedData");
    }
    const Vanetza_Security_SignedData_t& sd = *outer->content->choice.signedData;

    // Per TS 102 941 §6.2.3.2.2 the EA signs enrolment responses with signer = digest(EA cert).
    const HashedId8 ea_hid8 = ea_certificate.calculate_hashed_id8(security);
    if (sd.signer.present != Vanetza_Security_SignerIdentifier_PR_digest) {
        throw DecodingFailure("enrolment response must have signer = digest");
    }
    if (sd.signer.choice.digest != ea_hid8.octets) {
        throw VerificationFailure("enrolment response signer digest does not match EA certificate");
    }

    if (sd.tbsData->headerInfo.psid != aid::SCR) {
        throw DecodingFailure("enrolment response PSID is not SCR");
    }

    if (!validate(security, sd, ea_certificate.raw())) {
        throw VerificationFailure("enrolment response signature does not verify against EA certificate");
    }

    const Vanetza_Security_Opaque_t* inner_opaque = get_signed_payload(outer->content);
    if (!inner_opaque) {
        throw DecodingFailure("enrolment response carries no unsecured signed payload");
    }

    EnrolmentResponseData inner = EnrolmentResponseData::from_opaque(*inner_opaque);
    if (inner->version != Vanetza_Security_Version_v1) {
        throw DecodingFailure("inner EtsiTs102941Data version is not v1");
    }

    const Vanetza_Security_InnerEcResponse_t& ec_resp = inner->content.choice.enrolmentResponse;

    EnrolmentResponse result;
    result.code = EnrolmentResponseCode { ec_resp.responseCode };
    result.request_hash.assign(ec_resp.requestHash.buf, ec_resp.requestHash.buf + ec_resp.requestHash.size);

    if (ec_resp.certificate) {
        result.certificate = Certificate(*ec_resp.certificate);
    }

    if (ec_resp.responseCode == Vanetza_Security_EnrolmentResponseCode_ok && !result.certificate) {
        throw DecodingFailure("enrolment response code is ok but no certificate is included");
    }

    return result;
}

} // namespace pki
} // namespace vanetza
