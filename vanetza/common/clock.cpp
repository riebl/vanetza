#include <vanetza/common/clock.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace vanetza
{

const boost::posix_time::ptime& Clock::epoch()
{
    static const boost::posix_time::ptime epoch {
        boost::gregorian::date(2004, 1, 1),
        boost::posix_time::milliseconds(0)
    };
    return epoch;
}

Clock::time_point Clock::at(const boost::posix_time::ptime& t)
{
    auto delta = (t - epoch()).total_microseconds();
    Clock::time_point tp { std::chrono::microseconds(delta) };
    return tp;
}

Clock::date_time Clock::at(const Clock::time_point& t)
{
    std::chrono::microseconds delta = t.time_since_epoch();
    return Clock::epoch() + boost::posix_time::microseconds(delta.count());
}

Clock::time_point Clock::at(const std::string& at)
{
    return Clock::at(boost::posix_time::time_from_string(at));
}

std::string Clock::epoch_debug(){
    uint64_t useconds_epoch = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch())
            .count();
    auto useconds_decimal = static_cast<double>(useconds_epoch)/1e6;
    return std::to_string(useconds_decimal) + " | ";
}

} // namespace vanetza
