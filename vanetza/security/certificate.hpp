#ifndef CERTIFICATE_HPP_LWBWIAVL
#define CERTIFICATE_HPP_LWBWIAVL

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/serialization.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/signer_info.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>
#include <vanetza/security/validity_restriction.hpp>
#include <boost/optional/optional.hpp>
#include <boost/variant/get.hpp>

namespace vanetza
{
namespace security
{

/// described in TS 103 097 v1.2.1 (2015-06), section 6.1
struct Certificate
{
    SignerInfo signer_info;
    SubjectInfo subject_info;
    std::list<SubjectAttribute> subject_attributes;
    std::list<ValidityRestriction> validity_restriction;
    Signature signature;
    // certificate version is two, for conformance with the present standard
    uint8_t version() const { return 2; }

    /**
     * Get subject attribute of a certain type (if present)
     * \param type of subject attribute
     */
    const SubjectAttribute* get_attribute(SubjectAttributeType type) const;

    /**
     * Get validity restriction of a certain type (if present)
     * \param type of validity restriction
     */
    const ValidityRestriction* get_restriction(ValidityRestrictionType type) const;

    /**
     * Remove subject attribute of a certain type (if present)
     * \param type of subject attribute
     */
    void remove_attribute(SubjectAttributeType type);

    /**
     * Remove validity restriction of a certain type (if present)
     * \param type of validity restriction
     */
    void remove_restriction(ValidityRestrictionType type);

    /**
     * Add ITS-AID to certificate's subject attributes
     * \param aid ITS-AID
     */
    void add_permission(ItsAid aid);

    /**
     * Add ITS-AID along with SSP to certificate's subject attributes
     * \param aid ITS-AID
     * \param ssp Service Specific Permissions
     */
    void add_permission(ItsAid aid, const ByteBuffer& ssp);

    /**
     * Get subject attribute by type
     * \tparam T subject attribute type
     * \return subject attribute, nullptr if not found
     */
    template<SubjectAttributeType T>
    const subject_attribute_type<T>* get_attribute() const
    {
        using type = subject_attribute_type<T>;
        const SubjectAttribute* field = get_attribute(T);
        return boost::get<type>(field);
    }

    /**
     * Get validity restriction by type
     * \tparam T validity restriction type
     * \return validity restriction, nullptr if not found
     */
    template<ValidityRestrictionType T>
    const validity_restriction_type<T>* get_restriction() const
    {
        using type = validity_restriction_type<T>;
        const ValidityRestriction* field = get_restriction(T);
        return boost::get<type>(field);
    }
};

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

/**
 * \brief Calculates size of an certificate object
 *
 * \param cert
 * \return number of octets needed to serialize the object
 */
size_t get_size(const Certificate&);

/**
 * \brief Serializes an object into a binary archive
 *
 * \param ar archive to serialize in
 * \param cert to serialize
 */
void serialize(OutputArchive&, const Certificate&);

/**
 * \brief Deserializes an object from a binary archive
 *
 * \param ar archive with a serialized object at the beginning
 * \param cert to deserialize
 * \return size of the deserialized object
 */
size_t deserialize(InputArchive&, Certificate&);

/**
* \brief Serialize parts of a Certificate for signature calculation
*
* Uses version, signer_field, subject_info, subject_attributes (+ length),
* validity_restriction (+ length).
*
* \param cert certificate to be converted
* \return binary representation
*/
ByteBuffer convert_for_signing(const Certificate&);

/**
 * \brief Sort lists in the certificate to be in the correct order for serialization
 *
 * \param cert certificate to sort
 */
void sort(Certificate& certificate);

/**
 * \brief Extract public key from certificate
 * \param cert Certificate
 * \param backend Backend
 * \return Uncompressed public key (if available)
 */
boost::optional<Uncompressed> get_uncompressed_public_key(const Certificate&, Backend& backend);

/**
 * \brief Extract public ECDSA256 key from certificate
 * \param cert Certificate
 * \param backend Backend
 * \return public key (if available)
 */
boost::optional<ecdsa256::PublicKey> get_public_key(const Certificate&, Backend& backend);

/**
 * Calculate hash id of certificate
 * \param cert Certificate
 * \return hash
 */
HashedId8 calculate_hash(const Certificate&);

} // namespace security
} // namespace vanetza

#endif /* CERTIFICATE_HPP_LWBWIAVL */
