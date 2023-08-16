#ifndef BC8469A6_CC39_4826_A95E_DE639D68863B
#define BC8469A6_CC39_4826_A95E_DE639D68863B

#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace security
{

enum class CertificateInvalidReason
{
    Broken_Time_Period,
    Off_Time_Period,
    Unknown_Signer,
    Missing_Signature,
    Missing_Public_Key,
    Invalid_Signer,
    Invalid_Name,
    Excessive_Chain_Length,
    Off_Region,
    Inconsistent_With_Signer,
    Insufficient_ITS_AID,
    Missing_Subject_Assurance,
};

class CertificateValidity
{
public:
    CertificateValidity() = default;

    /**
     * Create CertificateValidity signalling an invalid certificate
     * \param reason Reason for invalidity
     */
    CertificateValidity(CertificateInvalidReason reason) : m_reason(reason) {}

    /**
     * \brief Create CertificateValidity signalling a valid certificate
     * This method is equivalent to default construction but should be more expressive.
     * \return validity
     */
    static CertificateValidity valid() { return CertificateValidity(); }

    /**
     * Check if status corresponds to a valid certificate
     * \return true if certificate is valid
     */
    operator bool() const { return !m_reason; }

    /**
     * \brief Get reason for certificate invalidity
     * This call is only safe if reason is available, i.e. check validity before!
     *
     * \return reason
     */
    CertificateInvalidReason reason() const { return *m_reason; }

private:
    boost::optional<CertificateInvalidReason> m_reason;
};
    
} // namespace security
} // namespace vanetza

#endif /* BC8469A6_CC39_4826_A95E_DE639D68863B */
