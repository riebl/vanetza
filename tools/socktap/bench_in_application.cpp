#include "bench_in_application.hpp"
#include <vanetza/btp/ports.hpp>
#include <vanetza/asn1/cam.hpp>
#include <boost/units/cmath.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <chrono>
#include <exception>
#include <functional>
#include <iostream>

// This is simple application that counts the incoming messages.

using namespace vanetza;
using namespace std::chrono;

BenchInApplication::BenchInApplication(const Clock::time_point& time_now, boost::asio::steady_timer& timer, milliseconds interval)
    : m_time_now(time_now), m_interval(interval), m_timer(timer)
{
    schedule_timer();
}

BenchInApplication::PortType BenchInApplication::port()
{
    return host_cast<uint16_t>(0);
}

Application::PromiscuousHook* BenchInApplication::promiscuous_hook()
{
    return this;
}

void BenchInApplication::tap_packet(const DataIndication& indication, const UpPacket& packet)
{
    m_received_messages++;
}

void BenchInApplication::indicate(const DataIndication& indication, UpPacketPtr packet)
{
    // do nothing here
}

void BenchInApplication::schedule_timer()
{
    m_timer.expires_from_now(m_interval);
    m_timer.async_wait(std::bind(&BenchInApplication::on_timer, this, std::placeholders::_1));
}

void BenchInApplication::on_timer(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    std::cout << "Received " << m_received_messages << " messages." << std::endl;
    m_received_messages = 0;

    schedule_timer();
}
