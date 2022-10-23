#ifndef BASIC_ELEMENTS_HPP_RALCTYHI
#define BASIC_ELEMENTS_HPP_RALCTYHI

#include <vanetza/common/clock.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <cstdint>

namespace vanetza
{
namespace security
{
namespace v2
{

using Time64 = uint64_t;
using Time32 = uint32_t;

/// Time64WithStandardDeviation specified in TS 103 097 v1.2.1, section 4.2.16
struct Time64WithStandardDeviation
{
    Time64 time64;
    uint8_t log_std_dev;
};

/**
 * Convert time point to time stamp
 * \param tp time point
 * \return time stamp with second accuracy
 */
Time32 convert_time32(const Clock::time_point& tp);

/**
 * Convert time point to time stamp
 * \param tp time point
 * \return time stamp with microsecond accuracy
 */
Time64 convert_time64(const Clock::time_point& tp);

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* BASIC_ELEMENTS_HPP_RALCTYHI */
