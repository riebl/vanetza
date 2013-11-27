#ifndef SOCKET_DESCRIPTOR_HPP_
#define SOCKET_DESCRIPTOR_HPP_

namespace vanetza
{

/**
 * SocketDescriptor closes raw socket descriptor during destruction.
 * This is only done if stored descriptor is valid.
 */
class SocketDescriptor
{
public:
    typedef int fd_t;

    SocketDescriptor();
    SocketDescriptor(fd_t fd);
    ~SocketDescriptor();
    // Don't allow copy operations (exclusive socket ownership)
    SocketDescriptor(const SocketDescriptor&) = delete;
    SocketDescriptor& operator=(const SocketDescriptor&) = delete;
    // Moving is okay, i.e. passing ownership
    SocketDescriptor(SocketDescriptor&& tmp) = default;
    SocketDescriptor& operator=(SocketDescriptor&& tmp) = default;

    operator fd_t() const { return m_socket_fd; }
    bool valid() const;

private:
    fd_t m_socket_fd;
};

} // namespace vanetza

#endif // SOCKET_DESCRIPTOR_HPP_

