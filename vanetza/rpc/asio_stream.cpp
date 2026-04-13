#include <vanetza/common/annotation.hpp>
#include <vanetza/rpc/asio_stream.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <kj/debug.h>

namespace vanetza
{
namespace rpc
{

namespace
{

class KjBufferSequence
{
public:
    using value_type = boost::asio::const_buffer;

    class const_iterator
    {
    public:
        using value_type = boost::asio::const_buffer;
        using difference_type = std::ptrdiff_t;
        using pointer = const value_type*;
        using reference = value_type;
        using iterator_category = std::forward_iterator_tag;

        const_iterator() = default;
        explicit const_iterator(const kj::ArrayPtr<const kj::byte>* ptr) : ptr_(ptr) {}

        value_type operator*() const { return boost::asio::const_buffer(ptr_->begin(), ptr_->size()); }
        const_iterator& operator++()
        {
            ++ptr_;
            return *this;
        }
        const_iterator operator++(int)
        {
            auto tmp = *this;
            ++ptr_;
            return tmp;
        }
        bool operator==(const const_iterator& other) const { return ptr_ == other.ptr_; }
        bool operator!=(const const_iterator& other) const { return ptr_ != other.ptr_; }

    private:
        const kj::ArrayPtr<const kj::byte>* ptr_ = nullptr;
    };

    explicit KjBufferSequence(kj::ArrayPtr<const kj::ArrayPtr<const kj::byte>> pieces) : pieces_(pieces) {}

    const_iterator begin() const { return const_iterator(pieces_.begin()); }
    const_iterator end() const { return const_iterator(pieces_.end()); }

private:
    kj::ArrayPtr<const kj::ArrayPtr<const kj::byte>> pieces_;
};

} // namespace

AsioStream::AsioStream(boost::asio::ip::tcp::socket socket) : socket_(std::move(socket))
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
    boost::asio::async_write(socket_, buf,
        [this, fulfiller = std::move(paf.fulfiller)](
            const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
            mark_unused(bytes_transferred);
            if (ec) {
                signalDisconnect(ec);
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
    boost::asio::async_write(socket_, KjBufferSequence(pieces),
        [this, fulfiller = std::move(paf.fulfiller)](
            const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
            mark_unused(bytes_transferred);
            if (ec) {
                signalDisconnect(ec);
                fulfiller->reject(KJ_EXCEPTION(FAILED, "write", ec.message()));
            } else {
                fulfiller->fulfill();
            }
        });
    return kj::mv(paf.promise);
}

kj::Promise<void> AsioStream::whenWriteDisconnected()
{
    if (!socket_.is_open()) {
        return kj::READY_NOW;
    }
    KJ_IF_MAYBE(p, disconnect_promise_) {
        return p->addBranch();
    } else {
        auto paf = kj::newPromiseAndFulfiller<void>();
        disconnect_fulfiller_ = kj::mv(paf.fulfiller);
        auto fork = paf.promise.fork();
        auto result = fork.addBranch();
        disconnect_promise_ = kj::mv(fork);
        return kj::mv(result);
    }
}

void AsioStream::signalDisconnect(const boost::system::error_code& ec)
{
    if (ec != boost::asio::error::operation_aborted) {
        boost::system::error_code ignored;
        socket_.close(ignored);
        KJ_IF_MAYBE(f, disconnect_fulfiller_) {
            (*f)->fulfill();
            disconnect_fulfiller_ = nullptr;
        }
    }
}

kj::Promise<size_t> AsioStream::tryRead(void* buffer, size_t minBytes, size_t maxBytes)
{
    auto paf = kj::newPromiseAndFulfiller<size_t>();
    boost::asio::async_read(socket_, boost::asio::buffer(buffer, maxBytes), boost::asio::transfer_at_least(minBytes),
        [this, fulfiller = std::move(paf.fulfiller)](
            const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
            if (ec) {
                signalDisconnect(ec);
                fulfiller->reject(KJ_EXCEPTION(FAILED, "read", ec.message()));
            } else {
                fulfiller->fulfill(kj::mv(bytes_transferred));
            }
        });
    return kj::mv(paf.promise);
}

} // namespace rpc
} // namespace vanetza
