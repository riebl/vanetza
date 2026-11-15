#pragma once
#include <vanetza/common/clock.hpp>
#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/credential_provider.hpp>
#include <system_error>

namespace vanetza
{
namespace security
{

class CryptoProvider;
class SecurityModule;

namespace v2
{

/**
 * \brief Credential provider with an authorization ticket of a generated root and authorization authority (AA)
 *
 * Keys of the chain are created by the SecurityModule and discarded with the provider.
 * The chain is no part of any PKI, i.e. only stations trusting its root can validate the ticket.
 * It is intended for experimenting with secured messages.
 */
class NaiveCredentialProvider : public CredentialProvider
{
public:
    /**
     * Create provider without any certificates yet, see issue_certificates()
     *
     * Security module and crypto provider have to outlive the provider.
     * \param module security module creating NIST P-256 keys and signing certificates
     * \param crypto crypto provider calculating certificate digests
     */
    NaiveCredentialProvider(SecurityModule& module, CryptoProvider& crypto);
    NaiveCredentialProvider(const NaiveCredentialProvider&) = delete;
    NaiveCredentialProvider& operator=(const NaiveCredentialProvider&) = delete;
    ~NaiveCredentialProvider() override;

    /**
     * Issue certificates valid from an hour before now
     *
     * The first successful call creates keys, root, AA and ticket, later calls renew the ticket with its key.
     * \param now current time
     * \return error, e.g. of the security module; certificates issued before are kept
     */
    std::error_code issue_certificates(Clock::time_point now);

    /**
     * \return ticket along with its AA for any aid, nullptr until certificates are issued
     */
    const Credential* signing_credential(ItsAid aid) override;

    /**
     * \return certificate of authority, nullptr until certificates are issued
     */
    const Certificate* aa_certificate() const;
    const Certificate* root_certificate() const;

private:
    std::error_code create_chain(Clock::time_point now);
    std::error_code issue_ticket(Clock::time_point now);
    void discard_keys();
    bool issued() const;

    SecurityModule& m_module;
    CryptoProvider& m_crypto;
    KeyReference m_root_key;
    KeyReference m_aa_key;
    Certificate m_root_certificate;
    Credential m_credential;
};

} // namespace v2
} // namespace security
} // namespace vanetza
