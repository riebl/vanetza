#ifndef LINUX_PACKET_SOCKET_HPP_1L2DW3ML
#define LINUX_PACKET_SOCKET_HPP_1L2DW3ML

#include "vanetza/common/byte_order.hpp"
#include "vanetza/net/osi_layer.hpp"
#include "vanetza/net/socket_descriptor.hpp"
#include "vanetza/net/socket_traits.hpp"
#include <cstdint>
#include <string>
#include <netpacket/packet.h>
#include <sys/socket.h>

struct timeval;

namespace vanetza
{

class MacAddress;
class Packet;

class LinuxPacketSocket
{
public:
    LinuxPacketSocket(const std::string& ifcName, uint16be_t protocol);
    LinuxPacketSocket(const LinuxPacketSocket&) = delete;
    LinuxPacketSocket& operator=(const LinuxPacketSocket&) = delete;

    int set_option(int level, int name, const void* value, socklen_t length);
    int get_option(int level, int name, void* value, socklen_t* length);
    ssize_t send_to(const MacAddress&, const Packet&);
    ssize_t recv(Packet&);
    bool wait_read(const timeval&);

private:
    SocketDescriptor mSockFd;
    int mInterfaceIndex;
    uint16be_t mProtocol;
};

} // namespace vanetza

#endif /* LINUX_PACKET_SOCKET_HPP_1L2DW3ML */

