#include "vanetza/rpc/asio_event_port.hpp"

#include <boost/asio/post.hpp>
#include <chrono>

namespace vanetza
{
namespace rpc
{

AsioEventPort::AsioEventPort(boost::asio::io_context& io) :
    io_(io),
    steady_timer_(io_),
    clock_(kj::systemPreciseMonotonicClock()),
    timer_(clock_.now())
{
}

bool AsioEventPort::wait()
{
    io_.run_one();
    advanceTime();
    armTimeout();
    return false;
}

bool AsioEventPort::poll()
{
    io_.poll();
    advanceTime();
    return false;
}

void AsioEventPort::setRunnable(bool runnable)
{
    if (runnable && loop_) {
        boost::asio::post(io_, [this]() {
            if (loop_ && loop_->isRunnable()) {
                loop_->run();
            }
        });
    }
}

void AsioEventPort::advanceTime()
{
    timer_.advanceTo(clock_.now());
}

void AsioEventPort::armTimeout()
{
    std::chrono::nanoseconds dt {
      timer_.timeoutToNextEvent(clock_.now(), kj::NANOSECONDS, kj::maxValue)
          .map([](uint64_t ns) { return ns; })
          .orDefault(0)
    };
    if (dt > std::chrono::nanoseconds::zero()) {
        steady_timer_.expires_after(dt);
        steady_timer_.async_wait([this](const boost::system::error_code& ec) {
            if (!ec) {
                advanceTime();
            }
        });
    }
}

} // namespace rpc
} // namespace vanetza
