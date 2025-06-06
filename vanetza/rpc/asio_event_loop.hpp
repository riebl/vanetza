#pragma once
#include <vanetza/rpc/asio_event_port.hpp>
#include <kj/async.h>

namespace vanetza
{
namespace rpc
{

class AsioEventLoop : public kj::EventLoop
{
public:
    AsioEventLoop(AsioEventPort& port) : kj::EventLoop(port)
    {
        port.setLoop(this);
    }
};

} // namespace rpc
} // namespace vanetza

