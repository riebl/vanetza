#pragma once
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>

namespace vanetza
{
namespace security
{
namespace v3
{

struct Certificate : public asn1::asn1c_oer_wrapper<EtsiTs103097Certificate_t>
{
    Certificate();

};

/**
 * Calculate hash id (digest) of v3 certificate
 * \param cert certificate
 * \return hash id
 */
HashedId8 calculate_hash(const Certificate& cert);

} // namespace v3
} // namespace security
} // namespace vanetza
