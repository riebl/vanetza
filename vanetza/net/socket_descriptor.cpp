#include "socket_descriptor.hpp"
#include <unistd.h>

namespace vanetza
{

static const SocketDescriptor::fd_t sc_invalid_fd = -1;

SocketDescriptor::SocketDescriptor() :
    m_socket_fd(sc_invalid_fd)
{
}

SocketDescriptor::SocketDescriptor(fd_t fd) :
    m_socket_fd(fd)
{
}

SocketDescriptor::~SocketDescriptor()
{
    if (valid()) {
        close(m_socket_fd);
    }
}

bool SocketDescriptor::valid() const
{
    return m_socket_fd != sc_invalid_fd;
}

} // namespace vanetza

