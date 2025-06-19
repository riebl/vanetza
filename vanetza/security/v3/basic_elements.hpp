#pragma once
#include <vanetza/common/clock.hpp>
#include <vanetza/asn1/support/OCTET_STRING.h>
#include <vanetza/common/byte_buffer.hpp>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{
namespace v3
{

using Time64 = uint64_t;
using Time32 = uint32_t;

/**
 * Convert time point to time stamp
 * \param tp time point
 * \return time stamp with second accuracy
 */
Time32 convert_time32(const Clock::time_point& tp);

/**
 * Convert time stamp to time point
 * \param t time stamp with second accuracy
 * \return time point
 */
Clock::time_point convert_time_point(const Time32& t);

/**
 * Convert time point to time stamp
 * \param tp time point
 * \return time stamp with microsecond accuracy
 */
Time64 convert_time64(const Clock::time_point& tp);

/**
 * Convert time stamp to time point
 * \param t time stamp with microsecond accuracy
 * \return time point
 */
Clock::time_point convert_time_point(const Time64& t);

} // namespace v3
} // namespace security
} // namespace vanetza
