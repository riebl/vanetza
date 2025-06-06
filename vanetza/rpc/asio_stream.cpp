#include <vanetza/rpc/asio_stream.hpp>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <kj/debug.h>

namespace vanetza
{
namespace rpc
{

AsioStream::AsioStream(boost::asio::ip::tcp::socket socket) :
    socket_(std::move(socket))
{
}

void AsioStream::shutdownWrite()
{
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
}

kj::Promise<void> AsioStream::write(const void* buffer, size_t size)
{
    auto paf = kj::newPromiseAndFulfiller<void>();
    boost::asio::const_buffer buf(buffer, size);
    boost::asio::async_write(socket_, buf, [fulfiller = std::move(paf.fulfiller)](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
        if (ec) {
            fulfiller->reject(KJ_EXCEPTION(FAILED, "write", ec.message()));
        } else {
            fulfiller->fulfill();
        }
    });

    return kj::mv(paf.promise);
}

kj::Promise<void> AsioStream::write(kj::ArrayPtr<const kj::ArrayPtr<const kj::byte>> pieces)
{
    auto paf = kj::newPromiseAndFulfiller<void>();
    std::vector<boost::asio::const_buffer> buffers;
    buffers.reserve(pieces.size());
    for (const auto& piece : pieces) {
        buffers.push_back(boost::asio::buffer(piece.begin(), piece.size()));
    }
    boost::asio::async_write(socket_, buffers, [fulfiller = std::move(paf.fulfiller)](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
        if (ec) {
            fulfiller->reject(KJ_EXCEPTION(FAILED, "write", ec.message()));
        } else {
            fulfiller->fulfill();
        }
    });
    return kj::mv(paf.promise);
}

kj::Promise<void> AsioStream::whenWriteDisconnected()
{
    return kj::NEVER_DONE;
}

kj::Promise<size_t> AsioStream::tryRead(void* buffer, size_t minBytes, size_t maxBytes)
{
    auto paf = kj::newPromiseAndFulfiller<size_t>();
    boost::asio::async_read(socket_,
        boost::asio::buffer(buffer, maxBytes),
        boost::asio::transfer_at_least(minBytes),
        [fulfiller = std::move(paf.fulfiller)](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
            if (ec) {
                fulfiller->reject(KJ_EXCEPTION(FAILED, "read", ec.message()));
            } else {
                fulfiller->fulfill(kj::mv(bytes_transferred));
            }
        });
    return kj::mv(paf.promise);
}


} // namespace rpc
} // namespace vanteza
