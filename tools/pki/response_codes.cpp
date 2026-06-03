#include "response_codes.hpp"
#include <string>

namespace vanetza
{
namespace pki
{

std::string to_string(EnrolmentResponseCode code)
{
    switch (code.value) {
        case Vanetza_Security_EnrolmentResponseCode_ok:
            return "ok";
        case Vanetza_Security_EnrolmentResponseCode_badcontenttype:
            return "bad content type";
        case Vanetza_Security_EnrolmentResponseCode_baditsstatus:
            return "bad ITS status";
        case Vanetza_Security_EnrolmentResponseCode_cantparse:
            return "cannot parse";
        case Vanetza_Security_EnrolmentResponseCode_decryptionfailed:
            return "decryption failed";
        case Vanetza_Security_EnrolmentResponseCode_deniedpermissions:
            return "denied permissions";
        case Vanetza_Security_EnrolmentResponseCode_deniedrequest:
            return "denied request";
        case Vanetza_Security_EnrolmentResponseCode_imnottherecipient:
            return "I am not the recipient";
        case Vanetza_Security_EnrolmentResponseCode_invalidencryptionkey:
            return "invalid encryption key";
        case Vanetza_Security_EnrolmentResponseCode_invalidkeys:
            return "invalid keys";
        case Vanetza_Security_EnrolmentResponseCode_invalidsignature:
            return "invalid signature";
        case Vanetza_Security_EnrolmentResponseCode_unknownencryptionalgorithm:
            return "unknown encryption algorithm";
        case Vanetza_Security_EnrolmentResponseCode_unknownits:
            return "unknown ITS";
        default:
            return "unknown";
    }
}

std::string to_string(AuthorizationResponseCode code)
{
    switch (code.value) {
        case Vanetza_Security_AuthorizationResponseCode_ok:
            return "ok";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_cantparse:
            return "its-aa: cannot parse";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_badcontenttype:
            return "its-aa: bad content type";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_imnottherecipient:
            return "its-aa: not the recipient";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_unknownencryptionalgorithm:
            return "its-aa: unknown encryption algorithm";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_decryptionfailed:
            return "its-aa: decryption failed";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_keysdontmatch:
            return "its-aa: keys don't match";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_incompleterequest:
            return "its-aa: incomplete request";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_invalidencryptionkey:
            return "its-aa: invalid encryption key";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_outofsyncrequest:
            return "its-aa: out-of-sync request";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_unknownea:
            return "its-aa: unknown EA";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_invalidea:
            return "its-aa: invalid EA";
        case Vanetza_Security_AuthorizationResponseCode_its_aa_deniedpermissions:
            return "its-aa: denied permissions";
        case Vanetza_Security_AuthorizationResponseCode_aa_ea_cantreachea:
            return "aa-ea: cannot reach EA";
        case Vanetza_Security_AuthorizationResponseCode_ea_aa_cantparse:
            return "ea-aa: cannot parse";
        case Vanetza_Security_AuthorizationResponseCode_ea_aa_badcontenttype:
            return "ea-aa: bad content type";
        case Vanetza_Security_AuthorizationResponseCode_ea_aa_imnottherecipient:
            return "ea-aa: not the recipient";
        case Vanetza_Security_AuthorizationResponseCode_ea_aa_unknownencryptionalgorithm:
            return "ea-aa: unknown encryption algorithm";
        case Vanetza_Security_AuthorizationResponseCode_ea_aa_decryptionfailed:
            return "ea-aa: decryption failed";
        case Vanetza_Security_AuthorizationResponseCode_invalidaa:
            return "invalid AA";
        case Vanetza_Security_AuthorizationResponseCode_invalidaasignature:
            return "invalid AA signature";
        case Vanetza_Security_AuthorizationResponseCode_wrongea:
            return "wrong EA";
        case Vanetza_Security_AuthorizationResponseCode_unknownits:
            return "unknown ITS";
        case Vanetza_Security_AuthorizationResponseCode_invalidsignature:
            return "invalid signature";
        case Vanetza_Security_AuthorizationResponseCode_invalidencryptionkey:
            return "invalid encryption key";
        case Vanetza_Security_AuthorizationResponseCode_deniedpermissions:
            return "denied permissions";
        case Vanetza_Security_AuthorizationResponseCode_deniedtoomanycerts:
            return "denied: too many certificates";
        default:
            return "unknown(" + std::to_string(static_cast<long>(code.value)) + ")";
    }
}

} // namespace pki
} // namespace vanetza
