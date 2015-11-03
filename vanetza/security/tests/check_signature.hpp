#ifndef CHECK_SIGNATURE_HPP_7RESWTUO
#define CHECK_SIGNATURE_HPP_7RESWTUO

#include <vanetza/security/signature.hpp>

namespace vanetza
{
namespace security
{

void check(const EcdsaSignature&, const EcdsaSignature&);
void check(const Signature&, const Signature&);

} // namespace security
} // namespace vanetza

#endif /* CHECK_SIGNATURE_HPP_7RESWTUO */

