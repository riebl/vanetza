#ifndef CHECK_SIGNATURE_HPP_7RESWTUO
#define CHECK_SIGNATURE_HPP_7RESWTUO

#include <vanetza/security/v2/signature.hpp>

namespace vanetza
{
namespace security
{

void check(const EcdsaSignature&, const EcdsaSignature&);
void check(const EcdsaSignatureFuture&, const EcdsaSignatureFuture&);

/**
 * \brief create a random EcdsaSignature
 * \param seed the optional seed for the RNG
 * \return created signature
 */
EcdsaSignature create_random_ecdsa_signature(int seed = 0);

namespace v2
{

void check(const Signature&, const Signature&);

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* CHECK_SIGNATURE_HPP_7RESWTUO */
