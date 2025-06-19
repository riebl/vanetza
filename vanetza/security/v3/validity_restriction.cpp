#include <vanetza/security/v3/validity_restriction.hpp>


namespace vanetza
{
namespace security
{
namespace v3
{

StartAndEndValidity::StartAndEndValidity(Time32 start, Time32 end) :
    start_validity(start), end_validity(end)
{
}

} // namespace v3
} // namespace security
} // namespace vanetza
