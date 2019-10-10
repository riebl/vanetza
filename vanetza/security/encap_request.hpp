#ifndef ENCAP_REQUEST_HPP_OX8CLPLW
#define ENCAP_REQUEST_HPP_OX8CLPLW

#include <vanetza/common/its_aid.hpp>
#include <vanetza/net/packet.hpp>

namespace vanetza
{
namespace security
{

/**
 * Security services to invoke when GN MIB's itsGnSecurity is enabled.
 *
 * When a SecurityProfile parameter is set to Default, the value Sign is used as a reasonable default.
 */
enum class SecurityProfile
{
    Default,
    Sign
    // TODO: Add Encrypt and SignAndEncrypt when encryption is supported
};

/**
 * Input data for encapsulating a packet in a secured message
 * \see TS 102 723-8 for SN-ENCAP.request
 */
struct EncapRequest {
    DownPacket plaintext_payload; // mandatory
    boost::optional<SecurityProfile> sec_services; // optional
    ItsAid its_aid; // mandatory
    ByteBuffer permissions; // mandatory
    // TODO: context_information (optional), target_id_list (optional):
    // Encryption is currently not supported
};

} // namespace security
} // namespace vanetza

#endif // ENCAP_REQUEST_HPP_OX8CLPLW
