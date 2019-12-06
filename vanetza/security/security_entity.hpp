#ifndef SECURITY_ENTITY_HPP
#define SECURITY_ENTITY_HPP

#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/decap_request.hpp>
#include <vanetza/security/encap_confirm.hpp>
#include <vanetza/security/encap_request.hpp>

namespace vanetza
{
namespace security
{

class SecurityEntity
{
public:
    /**
     * \brief Creates a security envelope covering the given payload.
     *
     * The payload consists of the CommonHeader, ExtendedHeader and the payload of
     * the layers above the network layer. The entire security envelope is used
     * to calculate a signature which gets added to the resulting SecuredMessage.
     *
     * \param request containing payload to sign
     * \return confirmation containing signed SecuredMessage
     */
    virtual EncapConfirm encapsulate_packet(EncapRequest&& request) = 0;

    /**
     * \brief Decapsulates the payload within a SecuredMessage
     *
     * Verifies the Signature and SignerInfo of a SecuredMessage.
     *
     * \param request containing a SecuredMessage
     * \return decapsulation confirmation including plaintext payload
     */
    virtual DecapConfirm decapsulate_packet(DecapRequest&& request) = 0;

    virtual ~SecurityEntity() = default;
};

} // namespace security
} // namespace vanetza

#endif // SECURITY_ENTITY_HPP
