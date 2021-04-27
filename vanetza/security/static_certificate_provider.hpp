#ifndef STATIC_CERTIFICATE_PROVIDER_HPP_MTULFLKX
#define STATIC_CERTIFICATE_PROVIDER_HPP_MTULFLKX

#include <vanetza/security/certificate_provider.hpp>

namespace vanetza
{
namespace security
{

/**
 * \brief A simple certificate provider
 *
 * This certificate provider uses a static certificate and key pair that is pre-generated.
 */
class StaticCertificateProvider : public CertificateProvider
{
public:
    /**
     * Create static certificate provider with empty chain
     * \param authorization_ticket
     * \param ticket_key private key of given authorization ticket
     */
    StaticCertificateProvider(const Certificate& authorization_ticket, const ecdsa256::PrivateKey& ticket_key);

    /**
     * Create static certificate provider with given chain
     * \param authorization_ticket
     * \param ticket_key private key of given authorization ticket
     * \param chain own certificate chain
     */
    StaticCertificateProvider(const Certificate& authorization_ticket, const ecdsa256::PrivateKey& ticket_key,
            const std::list<Certificate>& chain);

    /**
     * Get own certificate to use for signing
     * \return own certificate
     */
    virtual const Certificate& own_certificate() override;

    /**
     * Get own certificate chain, excluding the leaf certificate and root CA
     * \return own certificate chain
     */
    virtual std::list<Certificate> own_chain() override;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    virtual const ecdsa256::PrivateKey& own_private_key() override;

private:
    Certificate authorization_ticket;
    ecdsa256::PrivateKey authorization_ticket_key;
    std::list<Certificate> chain;
};


class StaticCertificateProviderV3 : public CertificateProviderV3
{
public:
    /**
     * Create static certificate provider with empty chain
     * \param authorization_ticket
     * \param ticket_key private key of given authorization ticket
     */
    StaticCertificateProviderV3(const CertificateV3& authorization_ticket, const ecdsa256::PrivateKey& ticket_key);

    /**
     * Create static certificate provider with given chain
     * \param authorization_ticket
     * \param ticket_key private key of given authorization ticket
     * \param chain own certificate chain
     */
    StaticCertificateProviderV3(const CertificateV3& authorization_ticket, const ecdsa256::PrivateKey& ticket_key,
            const std::list<CertificateV3>& chain);

    /**
     * Get own certificate to use for signing
     * \return own certificate
     */
    virtual const CertificateV3& own_certificate() override;

    /**
     * Get own certificate chain, excluding the leaf certificate and root CA
     * \return own certificate chain
     */
    virtual std::list<CertificateV3> own_chain() override;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    virtual const ecdsa256::PrivateKey& own_private_key() override;

private:
    CertificateV3 authorization_ticket;
    ecdsa256::PrivateKey authorization_ticket_key;
    std::list<CertificateV3> chain;
};



} // namespace security
} // namespace vanetza

#endif /* STATIC_CERTIFICATE_PROVIDER_HPP_MTULFLKX */
