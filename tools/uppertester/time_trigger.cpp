#include "time_trigger.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <iostream>
#include <functional>

namespace asio = boost::asio;
namespace posix_time = boost::posix_time;
using namespace vanetza;

TimeTrigger::TimeTrigger(asio::io_service& io_service) :
    m_io_service(io_service), m_timer(io_service), m_runtime(Clock::at(now()))
{
    std::cout << "Starting runtime at " << now() << std::endl;
    schedule();
}

posix_time::ptime TimeTrigger::now() const
{
    return posix_time::microsec_clock::universal_time();
}

void TimeTrigger::schedule()
{
    update_runtime();
    auto next = m_runtime.next();
    if (next < Clock::time_point::max()) {
        m_timer.expires_at(Clock::at(next));
        m_timer.async_wait(std::bind(&TimeTrigger::on_timeout, this, std::placeholders::_1));
    } else {
        m_timer.cancel();
    }
}

void TimeTrigger::on_timeout(const boost::system::error_code& ec)
{
    if (asio::error::operation_aborted != ec) {
        schedule();
    }
}

void TimeTrigger::update_runtime()
{
    auto current_time = now();
    m_runtime.trigger(Clock::at(current_time));
}
