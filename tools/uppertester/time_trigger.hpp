#ifndef UPPERTESTER_TIME_TRIGGER_HPP
#define UPPERTESTER_TIME_TRIGGER_HPP

#include <vanetza/common/runtime.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

class TimeTrigger
{
public:
    TimeTrigger(boost::asio::io_service&);
    vanetza::Runtime& runtime() { return m_runtime; }
    void schedule();

private:
    boost::posix_time::ptime now() const;
    void on_timeout(const boost::system::error_code&);
    void update_runtime();

    boost::asio::io_service& m_io_service;
    boost::asio::deadline_timer m_timer;
    vanetza::Runtime m_runtime;
};

#endif /* UPPERTESTER_TIME_TRIGGER_HPP */
