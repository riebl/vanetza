#ifndef SIGN_HEADER_POLICY_HPP_KJIIEGCH
#define SIGN_HEADER_POLICY_HPP_KJIIEGCH

#include <vanetza/common/clock.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/header_field.hpp>
#include <set>

namespace vanetza
{

// forward declaration
class PositionProvider;

namespace security
{

// forward declarations
class CertificateProvider;
struct SignRequest;

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
};

/**
 * DefaultSignHeaderPolicy implements the default behaviour specified by ETSI TS 103 097 V1.2.1
 */
class DefaultSignHeaderPolicy : public SignHeaderPolicy
{
public:
    DefaultSignHeaderPolicy(const Runtime&, PositionProvider& positioning);

    std::list<HeaderField> prepare_header(const SignRequest& request, CertificateProvider& certificate_provider) override;
    void request_unrecognized_certificate(HashedId8 id) override;
    void request_certificate() override;
    void request_certificate_chain() override;

private:
    const Runtime& m_runtime;
    PositionProvider& m_positioning;
    Clock::time_point m_cam_next_certificate;
    std::set<HashedId3> m_unknown_certificates;
    bool m_cert_requested;
    bool m_chain_requested;
};

} // namespace security
} // namespace vanetza

#endif /* SIGN_HEADER_POLICY_HPP_KJIIEGCH */
