#pragma once
#include <vanetza/common/clock.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/peer_request_tracker.hpp>
#include <boost/optional/optional.hpp>

namespace vanetza
{

// forward declaration
class PositionProvider;

namespace security
{

// forward declarations
class CertificateProvider;
struct SignRequest;

namespace v3
{


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
     * \param secured_message output message
     * \return header fields
     */
    virtual void prepare_header(const SignRequest& req, SecuredMessage& secured_message) = 0;

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
     * Enqueue a certificate for P2P distribution.
     * \param id hash of requested certificate
     */
    virtual void enqueue_p2p_request(HashedId3 id) = 0;

    /**
     * Discard a P2P certificate request.
     * \param id hash of requested certificate
     */
    virtual void discard_p2p_request(HashedId3 id) = 0;

    virtual ~SignHeaderPolicy() = default;
};

/**
 * DefaultSignHeaderPolicy implements the default behaviour specified by ETSI TS 103 097 V2.1.1
 */
class DefaultSignHeaderPolicy : public SignHeaderPolicy
{
public:
    DefaultSignHeaderPolicy(const Runtime&, PositionProvider& positioning, CertificateProvider&);

    void prepare_header(const SignRequest& request, SecuredMessage& secured_message) override;
    void request_unrecognized_certificate(HashedId8 id) override;
    void request_certificate() override;
    void enqueue_p2p_request(HashedId3) override;
    void discard_p2p_request(HashedId3) override;

private:
    const Runtime& m_runtime;
    PositionProvider& m_positioning;
    CertificateProvider& m_cert_provider;
    Clock::time_point m_cam_next_certificate;
    bool m_cert_requested;
    PeerRequestTracker m_incoming_requests;
    PeerRequestTracker m_outgoing_requests;
};

} // namespace v3
} // namespace security
} // namespace vanetza

