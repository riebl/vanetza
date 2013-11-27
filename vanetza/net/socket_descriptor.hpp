#ifndef SOCKET_DESCRIPTOR_HPP_
#define SOCKET_DESCRIPTOR_HPP_

#include <unistd.h>

namespace vanetza
{

class SocketDescriptor
{
public:
    typedef int fd_t;

    SocketDescriptor() : mSockFd(scInvalidFd) {}
    SocketDescriptor(fd_t fd) : mSockFd(fd) {}
    ~SocketDescriptor() { if (!invalid()) close(mSockFd); }
    // Don't allow copy operations (exclusive socket ownership)
    SocketDescriptor(const SocketDescriptor&) = delete;
    SocketDescriptor& operator=(const SocketDescriptor&) = delete;
    // Moving is okay, i.e. passing ownership
    SocketDescriptor(SocketDescriptor&& tmp);
    SocketDescriptor& operator=(SocketDescriptor&& tmp);

    operator fd_t() const { return mSockFd; }
    bool invalid() const { return mSockFd == scInvalidFd; }

    static const fd_t scInvalidFd = -1;

private:
    int mSockFd;
};

} // namespace vanetza

#endif // SOCKET_DESCRIPTOR_HPP_
