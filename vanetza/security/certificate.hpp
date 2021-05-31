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
#include <vanetza/asn1/etsi_certificate.hpp>
#include <vanetza/asn1/security/Certificate.h>

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

// described in TS 103 097 v1.3.1 (2017-10)
class CertificateV3{
    public:
        /**
         * \brief Constructor for the V1.3.1 Certificate. By default constructs the certificate with all values set to 0.
         */
        CertificateV3();
        ~CertificateV3();
        /**
         * \brief Constructor for the V1.3.1 Certificate.
         * \param certificate EtsiTs103097Certificate wrapper
         */
        CertificateV3(vanetza::asn1::EtsiTs103097Certificate& certificate);
        /**
         * \brief Constructor for the V1.3.1 Certificate.
         * \param coer_certificate ByteBuffer with a COER encoded certificate
         */
        CertificateV3(vanetza::ByteBuffer coer_certificate);
        /**
         * \brief Constructor for the V1.3.1 Certificate.
         * \param certificate Asn1c V1.3.1 certificate object
         */
        CertificateV3(const Certificate_t& certificate);
        /**
         * \brief Copy constructor for V1.3.1 Certificate
         * \param certificate Own object
         */
        CertificateV3(const CertificateV3& certificate);
        /**
         * \brief Serialize the v1.3.1 Certificate as specified in the standard
         * \return ByteBuffer with Certificate encoded in COER
         */
        vanetza::ByteBuffer serialize() const;
        /**
         * \brief Copies the Certificate to the pointer given to the function (as a Ieee1609.2)
         * \param cert Certificate pointer (Memory should be allocated)
         */
        void copy_into(Certificate_t* cert) const;
        /**
         * \brief The start and the end validity of the Certificate as it were a V1.2.1 Certificate
         * \return Start and end validity object
         */
        vanetza::security::StartAndEndValidity get_start_and_end_validity() const;
        /**
         * \brief The duration until the certificate expires
         * \return The duration 
         */
        Clock::duration get_validity_duration() const;
        /**
         * \brief Gives back the geographic region where the Certificate is valid
         * \return Shared pointer to the Geographic Region object
         */
        std::shared_ptr<GeographicRegion> get_geographic_region() const;
        /**
         * \brief Returns the list of the app permissions that the certificate has
         * \return List of ITS-AID (in V1.3.1 called PsidSsp_t)
         */
        std::list<PsidSsp_t> get_app_permissions() const;
        /**
         * \brief Returns the buffer of the serialized part on which then can be computed the signature
         * \return The serialization of the ToBeSigned part of the Certificate
         */
        vanetza::ByteBuffer convert_for_signing() const;
        /**
         * \brief Calculates the hash of the certificate
         * \return HashedId8 of the certificate
         */
        HashedId8 calculate_hash() const;
        /**
         * \brief Returns the issuer identifier
         * \return The hashedId8 of the issuer
         */
        HashedId8 get_issuer_identifier() const;
        /**
         * \brief Returns the signature of the Certificate
         * \return Signature object
         */
        Signature get_signature() const;
        /**
         * \brief Getter of the Subject Assurance
         * \return Shared pointer to the subject assurance
         */
        std::shared_ptr<SubjectAssurance> get_subject_assurance() const;
        /**
         * \brief Getter of the public key
         * \param backend Backend
         * \return optional of the public key
         */
        boost::optional<ecdsa256::PublicKey> get_public_key(Backend& backend) const;
        /**
         * \brief Getter of the public key (in uncompressed format)
         * \param backend Backend
         * \return public key (if available)
         */
        boost::optional<Uncompressed> get_uncompressed_public_key(Backend& backend) const;
        /**
         * \brief The version of the standard of the certificate
         * \return version (3)
         */
        uint8_t version() const { return 3; }
    private:
        void EccP256CurvePoint_to_x_only(EccP256CurvePoint_t& curve_point) const; //Needed to calculate hash
        
        vanetza::asn1::EtsiTs103097Certificate certificate;

};

void serialize(OutputArchive& ar, const CertificateV3& certificate);

enum class CertificateVariantVersion
{
    Two,
    Three
};

/**
 * \brief Calculates size of an certificate object
 *
 * \param cert
 * \return number of octets needed to serialize the object
 */
size_t get_size(const CertificateVariant&);

/**
 * \brief Serializes an object into a binary archive
 *
 * \param ar archive to serialize in
 * \param cert to serialize
 */
void serialize(OutputArchive&, const CertificateVariant&);

/**
 * \brief Deserializes an object from a binary archive
 *
 * \param ar archive with a serialized object at the beginning
 * \param cert to deserialize
 * \return size of the deserialized object
 */
size_t deserialize(InputArchive&, CertificateVariant&);

/**
* \brief Serialize parts of a Certificate (independent of the version) for signature calculation
*
* Depending on the version of the certificate will call one function or another.
*
* \param cert certificate to be converted (CertificateVariant)
* \return binary representation
*/
ByteBuffer convert_for_signing(const CertificateVariant&);


/**
 * \brief Extract public key from certificate
 * \param cert Certificate
 * \param backend Backend
 * \return Uncompressed public key (if available)
 */
boost::optional<Uncompressed> get_uncompressed_public_key(const CertificateVariant&, Backend& backend);

/**
 * \brief Extract public ECDSA256 key from any certificate
 * \param cert CertificateVariant
 * \param backend Backend
 * \return public key (if available)
 */
boost::optional<ecdsa256::PublicKey> get_public_key(const CertificateVariant& cert, Backend& backend);

/**
 * Calculate hash id of any certificate
 * \param cert Certificate
 * \return hash
 */
HashedId8 calculate_hash(const CertificateVariant&);



} // namespace security
} // namespace vanetza

#endif /* CERTIFICATE_HPP_LWBWIAVL */
