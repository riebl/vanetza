#include <vanetza/security/v2/basic_elements.hpp>
#include <algorithm>
#include <cassert>
#include <chrono>

namespace vanetza
{
namespace security
{
namespace v2
{

Time32 convert_time32(const Clock::time_point& tp)
{
    using std::chrono::duration_cast;
    using seconds = std::chrono::duration<Time32>;
    return duration_cast<seconds>(tp.time_since_epoch()).count();
}

Time64 convert_time64(const Clock::time_point& tp)
{
    using std::chrono::duration_cast;
    using microseconds = std::chrono::duration<Time64, std::micro>;
    return duration_cast<microseconds>(tp.time_since_epoch()).count();
}

} // namespace v2
} // namespace security
} // namespace vanetza
