#ifndef SECURITY_ENTITY_HPP
#define SECURITY_ENTITY_HPP

#include <vanetza/common/clock.hpp>
#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/decap_request.hpp>
#include <vanetza/security/encap_confirm.hpp>
#include <vanetza/security/encap_request.hpp>
#include <memory>

namespace vanetza
{
namespace security
{

class CertificateManager;

class SecurityEntity
{
public:
    /**
     * \param time_now timestamp referring to current time
     */
    SecurityEntity(const Clock::time_point& time_now);

    /** \brief encapsulates packet
     *
     * \param packet that should be encapsulated
     * \return encapsulated packet
     */
    EncapConfirm encapsulate_packet(const EncapRequest& encap_request);

    /** \brief decapsulates packet
     *
     * \param packet that should be decapsulated
     * \return decapsulated packet
     */
    DecapConfirm decapsulate_packet(const DecapRequest& decap_request);

private:
    /** \brief sign the packet
    *
    * \param encap request that was handed over
    * \return signed packet
    */
    EncapConfirm sign(const EncapRequest& encap_request);

    /** \brief verify the packet
    *
    * \param signed packet
    * \return verified packet
    */
    DecapConfirm verify(const DecapRequest& decap_request);

    std::shared_ptr<CertificateManager> m_certificate_manager;
};

} // namespace security
} // namespace vanetza

#endif // SECURITY_ENTITY_HPP
