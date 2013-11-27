#include "timestamp.hpp"

namespace vanetza
{

Timestamp::Timestamp()
{
    mInternal.tv_sec = 0;
    mInternal.tv_nsec = 0;
}

Timestamp::Timestamp(const internal_t& ts) : mInternal(ts)
{
}

bool operator==(const Timestamp& lhs, const Timestamp& rhs)
{
    return (lhs.mInternal.tv_sec == rhs.mInternal.tv_sec &&
            lhs.mInternal.tv_nsec == rhs.mInternal.tv_nsec);
}

bool operator<(const Timestamp& lhs, const Timestamp& rhs)
{
    if (lhs.mInternal.tv_sec < rhs.mInternal.tv_sec) {
        return true;
    } else if (lhs.mInternal.tv_sec == rhs.mInternal.tv_sec) {
        return (lhs.mInternal.tv_nsec < rhs.mInternal.tv_nsec);
    } else {
        return false;
    }
}

void setMonotonic(Timestamp& ts)
{
    clock_gettime(CLOCK_MONOTONIC_RAW, static_cast<Timestamp::internal_t*>(ts));
}

double calcIntervalSeconds(const Timestamp& start, const Timestamp& end)
{
    double seconds = 0.0;
    auto* pStart = static_cast<const Timestamp::internal_t*>(start);
    auto* pEnd = static_cast<const Timestamp::internal_t*>(end);
    seconds += pEnd->tv_sec - pStart->tv_sec;
    seconds += (double(pEnd->tv_nsec - pStart->tv_nsec)) / (1000 * 1000 * 1000);
    return seconds;
}

double calcIntervalMilliseconds(const Timestamp& start, const Timestamp& end)
{
    double milliseconds = 0.0;
    auto* pStart = static_cast<const Timestamp::internal_t*>(start);
    auto* pEnd = static_cast<const Timestamp::internal_t*>(end);
    milliseconds += (pEnd->tv_sec - pStart->tv_sec) * 1000.0;
    milliseconds += (pEnd->tv_nsec - pStart->tv_nsec) / (1000.0 * 1000.0);
    return milliseconds;
}

} // namespace vanetza

