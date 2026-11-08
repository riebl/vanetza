#ifndef SIGN_HEADER_POLICY_HPP_KJIIEGCH
#define SIGN_HEADER_POLICY_HPP_KJIIEGCH

#include <vanetza/common/clock.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/v2/header_field.hpp>
#include <set>

namespace vanetza
{

// forward declaration
class PositionProvider;

namespace security
{

// forward declarations
struct SignRequest;

namespace v2
{

// forward declarations
class CertificateProvider;
struct Credential;

/**
 * SignHeaderPolicy is used while signing messages
 *
 * SignHeaderPolicy determines the header fields to be included in the secured message.
 * Other components can influence the policy's behaviour by calling one of its "report" methods.
 */
class SignHeaderPolicy
{
public:
    /**
     * Prepare header fields for next secured message.
     *
     * \param req signing request (including ITS-AID for example)
     * \param certprvd available certificates
     * \return header fields
     */
    virtual std::list<HeaderField> prepare_header(const SignRequest& req, CertificateProvider& certprvd) = 0;

    /**
     * Prepare header fields for next secured message.
     *
     * \param req signing request (including ITS-AID for example)
     * \param credential signing credential, i.e. its certificate signs the message
     * \return header fields
     */
    virtual std::list<HeaderField> prepare_header(const SignRequest& req, const Credential& credential) = 0;

    /**
     * Mark certificate as unrecognized in next secured message
     * \param id hash of unknown certificate
     */
    virtual void request_unrecognized_certificate(HashedId8 id) = 0;

    /**
     * Request a full certificate to be included in next secured message
     */
    virtual void request_certificate() = 0;

    /**
     * Request a full certificate chain to be included in next secured message
     */
    virtual void request_certificate_chain() = 0;

    /**
     * Report a certificate requested by another station as unrecognized
     * \param id truncated hash of requested certificate, e.g. of the own certificate or its chain
     */
    virtual void report_certificate_request(HashedId3 id) = 0;

    virtual ~SignHeaderPolicy() = default;
};

/**
 * DefaultSignHeaderPolicy implements the default behaviour specified by ETSI TS 103 097 V1.2.1
 */
class DefaultSignHeaderPolicy : public SignHeaderPolicy
{
public:
    DefaultSignHeaderPolicy(const Runtime&, PositionProvider& positioning);

    std::list<HeaderField> prepare_header(const SignRequest& request, CertificateProvider& certificate_provider) override;
    std::list<HeaderField> prepare_header(const SignRequest& request, const Credential& credential) override;
    void request_unrecognized_certificate(HashedId8 id) override;
    void request_certificate() override;
    void request_certificate_chain() override;
    void report_certificate_request(HashedId3 id) override;

private:
    // header fields of a message signed by certificate, issuers in root CA → AA order excluding the root
    std::list<HeaderField> prepare_header(const SignRequest&, const Certificate&, std::list<Certificate> issuers);

    const Runtime& m_runtime;
    PositionProvider& m_positioning;
    Clock::time_point m_cam_next_certificate;
    std::set<HashedId3> m_unknown_certificates;
    std::set<HashedId3> m_requested_certificates;
    bool m_cert_requested;
    bool m_chain_requested;
};

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* SIGN_HEADER_POLICY_HPP_KJIIEGCH */
