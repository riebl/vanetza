#pragma once
#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/secured_message.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

bool check_generation_time(const SecuredMessage& message, Clock::time_point now);
bool check_generation_location(const SecuredMessage& message, const Certificate& cert);
bool check_certificate_time(const Certificate& certificate, Clock::time_point now);
bool check_certificate_region(const Certificate& certificate, const PositionFix& position);

} // namespace v2
} // namespace security
} // namespace vanetza
