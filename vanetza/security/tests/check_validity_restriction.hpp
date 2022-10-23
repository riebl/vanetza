#ifndef CHECK_VALIDITY_RESTRICTION_HPP_W8OY9526
#define CHECK_VALIDITY_RESTRICTION_HPP_W8OY9526

#include <vanetza/security/v2/validity_restriction.hpp>
#include <vanetza/security/tests/check_list.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

void check(EndValidity, EndValidity);
void check(const StartAndEndValidity&, const StartAndEndValidity&);
void check(const StartAndDurationValidity&, const StartAndDurationValidity&);
void check(const ValidityRestriction&, const ValidityRestriction&);

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* CHECK_VALIDITY_RESTRICTION_HPP_W8OY9526 */
