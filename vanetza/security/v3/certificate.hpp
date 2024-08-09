#pragma once
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/security/hashed_id.hpp>
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

    void add_permission(ItsAid aid, const ByteBuffer& ssp);

    void add_cert_permission(asn1::PsidGroupPermissions* group_permission);

    void set_signature(const SomeEcdsaSignature& signature);

    ByteBuffer serialize();

    ByteBuffer convert_for_signing();
};

/**
 * Calculate hash id (digest) of v3 certificate
 * \param cert certificate
 * \return hash id if possible
 */
boost::optional<HashedId8> calculate_hash(const asn1::EtsiTs103097Certificate& cert);

/**
 * Extract the public key out of a certificate
 * \param cert certificate
 * \return public key if possible
 */
boost::optional<PublicKey> get_public_key(const asn1::EtsiTs103097Certificate& cert);

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
