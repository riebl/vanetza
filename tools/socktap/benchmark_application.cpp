#include "benchmark_application.hpp"
#include <chrono>
#include <iostream>

// Benchmark application counts all incoming messages and calculates the message rate.

using namespace std::chrono;
using namespace vanetza;

BenchmarkApplication::BenchmarkApplication(boost::asio::io_service& io) :
    m_timer(io), m_interval(std::chrono::seconds(1))
{
    schedule_timer();
}

BenchmarkApplication::PortType BenchmarkApplication::port()
{
    return host_cast<uint16_t>(0);
}

Application::PromiscuousHook* BenchmarkApplication::promiscuous_hook()
{
    return this;
}

void BenchmarkApplication::tap_packet(const DataIndication& indication, const UpPacket& packet)
{
    ++m_received_messages;
}

void BenchmarkApplication::indicate(const DataIndication& indication, UpPacketPtr packet)
{
    // do nothing here
}

void BenchmarkApplication::schedule_timer()
{
    m_timer.expires_from_now(m_interval);
    m_timer.async_wait(std::bind(&BenchmarkApplication::on_timer, this, std::placeholders::_1));
}

void BenchmarkApplication::on_timer(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    std::cout << "Received " << m_received_messages << " messages/second" << std::endl;
    m_received_messages = 0;

    schedule_timer();
}
