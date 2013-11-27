#include "io_vector.hpp"
#include "linux_packet_socket.hpp"
#include "mac_address.hpp"
#include "packet.hpp"
#include "sockaddr.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_order.hpp>
#include <vanetza/common/errno_exception.hpp>
#include <errno.h>
#include <net/if.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace vanetza
{

LinuxPacketSocket::LinuxPacketSocket(const std::string& ifcName, uint16be_t protocol) :
    mInterfaceIndex(if_nametoindex(ifcName.c_str())), mProtocol(protocol)
{
    mSockFd = socket(AF_PACKET, SOCK_DGRAM, mProtocol.get());
    if (mSockFd.invalid()) {
        throw ErrnoException(errno);
    }

    sockaddr_ll dest;
    dest.sll_family = AF_PACKET;
    dest.sll_protocol = mProtocol.get();
    dest.sll_ifindex = mInterfaceIndex;

    if (0 == dest.sll_ifindex) {
         throw std::runtime_error("Network interface name does not exist");
    }
    if (-1 == bind(mSockFd, (sockaddr*) &dest, sizeof(sockaddr_ll))) {
        throw ErrnoException(errno);
    }
}

int LinuxPacketSocket::set_option(int level, int name, const void* value, socklen_t length)
{
    return setsockopt(mSockFd, level, name, value, length);
}

int LinuxPacketSocket::get_option(int level, int name, void* value, socklen_t* length)
{
    return getsockopt(mSockFd, level, name, value, length);
}

ssize_t LinuxPacketSocket::send_to(const MacAddress& address, const Packet& packet)
{
    sockaddr_ll addr;
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = mProtocol.get();
    addr.sll_ifindex = mInterfaceIndex;
    assign(addr, address);

    msghdr hdr;
    hdr.msg_name = &addr;
    hdr.msg_namelen = sizeof(sockaddr_ll);

    IoVector iov;
    iov.append(packet);
    hdr.msg_iov = const_cast<iovec*>(iov.base());
    hdr.msg_iovlen = iov.length();

    const msghdr* pMsgHdr = &hdr;
    return ::sendmsg(mSockFd, pMsgHdr, 0);
}

ssize_t LinuxPacketSocket::recv(Packet& packet)
{
    ByteBuffer buffer(2048); // 2kB should be enough for a single packet, huh?
    ssize_t bytes = ::recv(mSockFd, &buffer[0], buffer.size(), 0);
    buffer.resize(bytes);
    packet[OsiLayer::Network].swap(buffer);
    return bytes;
}

bool LinuxPacketSocket::wait_read(const timeval& timeout)
{
    timeval timeout_copy = timeout;

    fd_set socket_set;
    fd_set empty_set;
    FD_ZERO(&socket_set);
    FD_SET(mSockFd, &socket_set);
    FD_ZERO(&empty_set);

    int fds = select(mSockFd + 1, &socket_set, &empty_set, &empty_set, &timeout_copy);
    if (-1 == fds) {
        if (errno == EINTR) {
            return false;
        } else {
            throw ErrnoException(errno);
        }
    } else if (0 == fds) {
        return false;
    } else {
        return true;
    }
}

} // namespace vanetza

