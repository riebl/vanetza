#ifndef COHDA_RAW_SOCKET_HPP_JARM8ALF
#define COHDA_RAW_SOCKET_HPP_JARM8ALF

#include "vanetza/common/byte_order.hpp"
#include "vanetza/net/osi_layer.hpp"
#include "vanetza/net/socket_descriptor.hpp"
#include "vanetza/net/socket_traits.hpp"
#include <string>

class Packet;
struct timeval;

class CohdaRawSocket
{
public:
    CohdaRawSocket(const std::string& ifcName, uint16be_t proto);
    ssize_t send(const Packet&);
    ssize_t recv(Packet&);
    bool wait_read(const timeval&);

private:
    SocketDescriptor mSockFd;
    uint16be_t mEthProto;
};


template<>
struct socket_layer_pdu<CohdaRawSocket, OsiLayer::Physical>
{
    typedef pdu_tags::mk2_tag tag;
};

template<>
struct socket_layer_pdu<CohdaRawSocket, OsiLayer::Link>
{
    typedef pdu_tags::ethernet_tag tag;
};

#endif /* COHDA_RAW_SOCKET_HPP_JARM8ALF */
