#include "cohda_raw_socket.hpp"
#include "mk2_descriptor.hpp"
#include "vanetza/common/errno_exception.hpp"
#include "vanetza/net/ethernet_header.hpp"
#include "vanetza/net/io_vector.hpp"
#include "vanetza/net/packet.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/select.h>
#include <sys/socket.h>

CohdaRawSocket::CohdaRawSocket(const std::string& ifcName, uint16be_t proto) :
    mEthProto(proto)
{
    mSockFd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (mSockFd.invalid()) {
        throw ErrnoException(errno);
    }

    sockaddr_ll sockAddr;
    sockAddr.sll_family = AF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ALL);
    sockAddr.sll_ifindex = if_nametoindex(ifcName.c_str());

    if (0 == sockAddr.sll_ifindex) {
        throw std::runtime_error("Network interface name does not exist");
    }
    if (-1 == bind(mSockFd, (sockaddr*) &sockAddr, sizeof(sockaddr_ll))) {
        throw ErrnoException(errno);
    }
}

ssize_t CohdaRawSocket::send(const Packet& packet)
{
    msghdr hdr;
    IoVector data { packet };
    assignIoVec(hdr, data);

    return sendmsg(mSockFd, &hdr, 0);
}

ssize_t CohdaRawSocket::recv(Packet& packet)
{
    ByteBuffer buffer(2048);
    ssize_t bytes = ::recv(mSockFd, &buffer[0], buffer.size(), 0);
    buffer.resize(std::max(bytes, static_cast<ssize_t>(0)));

    static const unsigned scRxDescriptorBytes = sizeof(tMK2RxDescriptor);
    static const unsigned scEthernetHdrBytes = getEthernetHeaderLength();
    static const unsigned scFcsBytes = 4;

    if (buffer.size() >= scRxDescriptorBytes + scEthernetHdrBytes + scFcsBytes) {
        const unsigned cPayloadBytes = buffer.size() - scRxDescriptorBytes
            - scEthernetHdrBytes - scFcsBytes;
        packet.clear();
        const uint8_t* buf = &buffer[0];
        std::copy(buf, buf + scRxDescriptorBytes, std::back_inserter(packet[OsiLayer::Physical]));
        buf += scRxDescriptorBytes;
        std::copy(buf, buf + scEthernetHdrBytes, std::back_inserter(packet[OsiLayer::Link]));
        buf += scEthernetHdrBytes;
        std::copy_n(buf, cPayloadBytes, std::back_inserter(packet[OsiLayer::Network]));
    } else {
        // Something is wrong
        return -1;
    }

    return bytes;
}

bool CohdaRawSocket::wait_read(const timeval& timeout)
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
