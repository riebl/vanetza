#ifndef BENCH_IN_APPLICATION_HPP_EUIC2VFR
#define BENCH_IN_APPLICATION_HPP_EUIC2VFR

#include "application.hpp"
#include <vanetza/btp/port_dispatcher.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/clock.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>

class BenchInApplication : public Application, public vanetza::btp::PortDispatcher::PromiscuousHook
{
public:
    BenchInApplication(const vanetza::Clock::time_point& time_now, boost::asio::steady_timer&, std::chrono::milliseconds interval);
    PortType port() override;
    void indicate(const DataIndication&, UpPacketPtr) override;
    void tap_packet(const DataIndication&, const vanetza::UpPacket&) override;

private:
    void schedule_timer();
    void on_timer(const boost::system::error_code& ec);

    const vanetza::Clock::time_point& m_time_now;
    std::chrono::milliseconds m_interval;
    boost::asio::steady_timer& m_timer;
    unsigned m_received_messages;
};

#endif /* BENCH_IN_APPLICATION_HPP_EUIC2VFR */
