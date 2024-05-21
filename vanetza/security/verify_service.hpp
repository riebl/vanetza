#ifndef VERIFY_SERVICE_HPP_BR4ISDBH
#define VERIFY_SERVICE_HPP_BR4ISDBH

#include <boost/optional.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/certificate_validity.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/secured_message.hpp>
#include <functional>

namespace vanetza
{
namespace security
{


enum class VerificationReport
{
    Success,
    False_Signature,
    Invalid_Certificate,
    Revoked_Certificate,
    Inconsistent_Chain,
    Invalid_Timestamp,
    Duplicate_Message,
    Invalid_Mobility_Data,
    Unsigned_Message,
    Signer_Certificate_Not_Found,
    Unsupported_Signer_Identifier_Type,
    Incompatible_Protocol,
    Configuration_Problem,
};

// mandatory parameters of SN-VERIFY.request (TS 102 723-8 V1.1.1)
struct VerifyRequest
{
    VerifyRequest(const SecuredMessage* msg) : secured_message(msg) {}
    const SecuredMessage* secured_message; /*< contains security header and payload */
};

// parameters of SN-VERIFY.confirm (TS 102 723-8 V1.1.1)
struct VerifyConfirm
{
    VerificationReport report; // mandatory
    ItsAid its_aid; // mandatory
    ByteBuffer permissions; // mandatory
    CertificateValidity certificate_validity; // non-standard extension
    boost::optional<HashedId8> certificate_id; // optional
};

/**
 * Equivalent of SN-VERIFY service in TS 102 723-8 V1.1.1
 */
class VerifyService
{
public:
    virtual ~VerifyService() = default;
    virtual VerifyConfirm verify(const VerifyRequest&) = 0;
};


/**
 * Get insecure dummy verify service without any checks
 */
class DummyVerifyService : public VerifyService
{
public:
    /**
     * \param report predefined confirm report result
     * \param validity predefined certificate validity result 
     */
    DummyVerifyService(VerificationReport report, CertificateValidity validity);
    VerifyConfirm verify(const VerifyRequest&) override;

private:
    VerificationReport m_report;
    CertificateValidity m_validity;
};

} // namespace security
} // namespace vanetza

#endif /* VERIFY_SERVICE_HPP_BR4ISDBH */
