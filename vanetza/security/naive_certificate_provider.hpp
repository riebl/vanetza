#ifndef NAIVE_CERTIFICATE_PROVIDER_HPP_MTULFLKX
#define NAIVE_CERTIFICATE_PROVIDER_HPP_MTULFLKX

#include <string>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate_provider.hpp>

namespace vanetza
{
namespace security
{

/**
 * \brief A very simplistic certificate provider
 *
 * This certificate provider signs its certificates with a randomly generated root certificate. This means the
 * signatures produced based on this certificate provider can't be verified by other parties.
 *
 * It's intended for experimenting with secured messages without validating signatures.
 */
class NaiveCertificateProvider : public CertificateProvider
{
public:
    NaiveCertificateProvider(const Runtime&);

    /**
     * \brief get own certificate for signing
     * \return own certificate
     */
    const Certificate& own_certificate() override;

    /**
     * Get own certificate chain, excluding the leaf certificate and root CA
     * \return own certificate chain
     */
    std::list<Certificate> own_chain() override;

    /**
     * \brief get own private key
     * \return private key
     */
    const ecdsa256::PrivateKey& own_private_key() override;

    /**
     * \brief get ticket signer certificate (same for all instances)
     * \return signing authorization authority certificate
     */
    const Certificate& aa_certificate();

    /**
     * \brief get root certificate (same for all instances)
     * \return signing root certificate
     */
    const Certificate& root_certificate();

    /**
     * \brief generate an authorization ticket
     * \return generated certificate
     */
    Certificate generate_authorization_ticket();

    /**
     * \brief sign an authorization ticket
     * \param certificate certificate to sign
     */
    void sign_authorization_ticket(Certificate& certificate);

private:
    /**
     * \brief get root key (same for all instances)
     * \return root key
     */
    const ecdsa256::KeyPair& aa_key_pair();

    /**
     * \brief get root key (same for all instances)
     * \return root key
     */
    const ecdsa256::KeyPair& root_key_pair();

    /**
     * \brief generate a authorization authority certificate
     *
     * \return generated certificate
     */
    Certificate generate_aa_certificate(const std::string& subject_name);

    /**
     * \brief generate a root certificate
     *
     * \return generated certificate
     */
    Certificate generate_root_certificate(const std::string& subject_name);

    BackendCryptoPP m_crypto_backend; /*< key generation is not a generic backend feature */
    const Runtime& m_runtime;
    const ecdsa256::KeyPair m_own_key_pair;
    Certificate m_own_certificate;
};

} // namespace security
} // namespace vanetza

#endif /* NAIVE_CERTIFICATE_PROVIDER_HPP_MTULFLKX */
