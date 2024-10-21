#pragma once
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/v3/asn1_types.hpp>
#include <boost/optional/optional_fwd.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

// forward declaration
class Certificate;

/**
 * Read-only view on a certificate
 * 
 * In contrast to Certificate, a view does not own the certificate data.
 * A view can be created with low overhead as no heavy copying is required.
 */
class CertificateView
{
public:
    explicit CertificateView(const asn1::EtsiTs103097Certificate* cert);

    /**
     * Calculate digest of certificate
     * \return digest if possible
     */
    boost::optional<HashedId8> calculate_digest() const;

    /**
     * Get verification key type
     * \return verification key type if possible; otherwise unspecified
     */
    KeyType get_verification_key_type() const;

    /**
     * Get issuer digest (if any)
     * \return issuer digest
     */
    boost::optional<HashedId8> issuer_digest() const;

    /**
     * Check if certificate is a Certification Authority certificate
     * \return true if certificate is a CA certificate
     */
    bool is_ca_certificate() const;

    /**
     * Check if certificate is an Authorization Ticket certificate
     * \return true if certificate is an AT certificate
     */
    bool is_at_certificate() const;

    /**
     * Check if certificate has an region restriction
     * \return true if certificate is only valid within a specific region
     */
    bool has_region_restriction() const;

    /**
     * Check if certificate is valid at given location
     * 
     * \param location location to be checked
     * \return true if certificate is valid at location
     */
    bool valid_at_location(const PositionFix& location) const;

    /**
     * Check if certificate is valid at given time point
     * 
     * \param time_point time point to be checked
     * \return true if certificate is valid at time point
     */
    bool valid_at_timepoint(const Clock::time_point& time_point) const;

    /**
     * Check if certificate is valid for given application
     * 
     * \param aid application to be checked
     * \return true if certificate is valid for application
     */
    bool valid_for_application(ItsAid aid) const;

    /**
     * Check if certificate has a canonical format
     * \return true if certificate is in canonical format
     */
    bool is_canonical() const;

    /**
     * Convert certificate into its canonical format if possible.
     * \return canonical certificate (or none if conversion failed)
     */
    boost::optional<Certificate> canonicalize() const;

    /**
     * Encode certificate.
     * \return encoded certificate
     */
    ByteBuffer encode() const;

protected:
    const asn1::EtsiTs103097Certificate* m_cert = nullptr;
};

struct Certificate : public asn1::asn1c_oer_wrapper<asn1::EtsiTs103097Certificate>, public CertificateView
{
    using Wrapper = asn1::asn1c_oer_wrapper<asn1::EtsiTs103097Certificate>;

    Certificate();
    explicit Certificate(const asn1::EtsiTs103097Certificate&);

    Certificate(const Certificate&);
    Certificate& operator=(const Certificate&);

    Certificate(Certificate&&);
    Certificate& operator=(Certificate&&);

    // resolve ambiguity
    ByteBuffer encode() const;

    void add_permission(ItsAid aid, const ByteBuffer& ssp);

    void add_cert_permission(asn1::PsidGroupPermissions* group_permission);

    void set_signature(const SomeEcdsaSignature& signature);
};

/**
 * Calculate digest of v3 certificate
 * \param cert certificate
 * \return digest if possible
 */
boost::optional<HashedId8> calculate_digest(const asn1::EtsiTs103097Certificate& cert);

/**
 * Check if certificate is in canonical format suitable for digest calculation.
 * \param cert certificate
 * \return true if certificate is in canonical format
 */
bool is_canonical(const asn1::EtsiTs103097Certificate& cert);

/**
 * Convert certificate into its canonical format if possible.
 * \param cert certificate
 * \return canonical certificate (or none if conversion failed)
 */
boost::optional<Certificate> canonicalize(const asn1::EtsiTs103097Certificate& cert); 

/**
 * Check if certificate is valid at given location
 * 
 * \param cert certificate to be checked
 * \param location location to be checked
 * \return true if certificate is valid at location
 */
bool valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location);

/**
 * Check if certificate is valid at given time point
 * 
 * \param cert certificate to be checked
 * \param time_point time point to be checked
 * \return true if certificate is valid at time point
 */
bool valid_at_timepoint(const asn1::EtsiTs103097Certificate& cert, const Clock::time_point& time_point);

/**
 * Check if certificate is valid for given application
 *
 * \param cert certificate to be checked
 * \param aid application to be checked
 * \return true if certificate is valid for application
 */
bool valid_for_application(const asn1::EtsiTs103097Certificate& cert, ItsAid aid);

/**
 * Extract the public key out of a certificate
 * \param cert certificate
 * \return public key if possible
 */
boost::optional<PublicKey> get_public_key(const asn1::EtsiTs103097Certificate& cert);

/**
 * Get verification key type
 * \param cert certificate
 * \return verification key type (maybe unspecified)
 */
KeyType get_verification_key_type(const asn1::EtsiTs103097Certificate& cert);

/**
 * Get application permissions (SSP = service specific permissions)
 * \param cert certificate containing application permissions
 * \param aid look up permissions for this application identifier
 * \return SSP bitmap or empty buffer
 */
ByteBuffer get_app_permissions(const asn1::EtsiTs103097Certificate& cert, ItsAid aid);

void add_psid_group_permission(asn1::PsidGroupPermissions* group_permission, ItsAid aid, const ByteBuffer& ssp, const ByteBuffer& bitmask);

void serialize(OutputArchive& ar, Certificate& certificate);

Certificate fake_certificate();

} // namespace v3
} // namespace security
} // namespace vanetza
