#pragma once
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>
#include <kj/async-io.h>

namespace vanetza
{
namespace rpc
{

class AsioStream : public kj::AsyncIoStream
{
public:
    AsioStream(boost::asio::ip::tcp::socket socket);

    void shutdownWrite() override;
    kj::Promise<void> write(const void* buffer, size_t size) override;
    kj::Promise<void> write(kj::ArrayPtr<const kj::ArrayPtr<const kj::byte>> pieces) override;
    kj::Promise<void> whenWriteDisconnected() override;
    kj::Promise<size_t> tryRead(void* buffer, size_t minBytes, size_t maxBytes) override;

private:
    void signalDisconnect(const boost::system::error_code& ec);

    boost::asio::ip::tcp::socket socket_;
    kj::Maybe<kj::ForkedPromise<void>> disconnect_promise_;
    kj::Maybe<kj::Own<kj::PromiseFulfiller<void>>> disconnect_fulfiller_;
};

} // namepsace rpc
} // namespace vanetza
