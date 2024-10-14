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

struct Certificate : public asn1::asn1c_oer_wrapper<asn1::EtsiTs103097Certificate>
{
    Certificate();
    explicit Certificate(const asn1::EtsiTs103097Certificate&);

    void add_permission(ItsAid aid, const ByteBuffer& ssp);

    void add_cert_permission(asn1::PsidGroupPermissions* group_permission);

    void set_signature(const SomeEcdsaSignature& signature);

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
     * Check if certificate is a Certification Authority certificate
     * \return true if certificate is a CA certificate
     */
    bool is_ca_certificate() const;

    /**
     * Check if certificate is an Authorization Ticket certificate
     * \return true if certificate is an AT certificate
     */
    bool is_at_certificate() const;
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
