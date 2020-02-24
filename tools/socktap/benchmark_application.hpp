#ifndef BENCHMARK_APPLICATION_HPP_EUIC2VFR
#define BENCHMARK_APPLICATION_HPP_EUIC2VFR

#include "application.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>

class BenchmarkApplication : public Application, private Application::PromiscuousHook
{
public:
    BenchmarkApplication(boost::asio::io_service&);
    PortType port() override;
    void indicate(const DataIndication&, UpPacketPtr) override;
    Application::PromiscuousHook* promiscuous_hook() override;

private:
    void schedule_timer();
    void on_timer(const boost::system::error_code& ec);
    void tap_packet(const DataIndication&, const vanetza::UpPacket&) override;

    boost::asio::steady_timer m_timer;
    std::chrono::milliseconds m_interval;
    unsigned m_received_messages;
};

#endif /* BENCHMARK_APPLICATION_HPP_EUIC2VFR */
