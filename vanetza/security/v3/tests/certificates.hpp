#pragma once
#include <vanetza/common/clock.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/v3/certificate.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * Create an unsigned authorization ticket of a public key permitting DENM for 168 hours.
 * Its issuer is fictitious, i.e. it is no part of a validatable certificate chain.
 */
Certificate make_authorization_ticket(const PublicKey& key, Clock::time_point start);

/**
 * Create an unsigned authorization authority certificate of a public key permitted to issue any permission.
 * Its issuer is fictitious like the one of make_authorization_ticket.
 */
Certificate make_authorization_authority(const PublicKey& key, Clock::time_point start);

} // namespace v3
} // namespace security
} // namespace vanetza
