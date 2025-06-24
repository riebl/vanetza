#pragma once
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <kj/async.h>
#include <kj/timer.h>

namespace vanetza
{
namespace rpc
{

class AsioEventPort : public kj::EventPort
{
public:
    AsioEventPort(boost::asio::io_context& io);

    bool wait() override;
    bool poll() override;
    void setRunnable(bool runnable) override;

    void setLoop(kj::EventLoop* loop)
    {
        loop_ = loop;
    }

    kj::Timer& getTimer()
    {
        return timer_;
    }

private:
    void advanceTime();
    void armTimeout();

    boost::asio::io_context& io_;
    boost::asio::steady_timer steady_timer_;
    kj::EventLoop* loop_ = nullptr;
    const kj::MonotonicClock& clock_;
    kj::TimerImpl timer_;
};

} // namespace rpc
} // namespace vanetza
