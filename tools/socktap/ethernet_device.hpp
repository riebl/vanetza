#ifndef ETHERNET_DEVICE_HPP_NEVC5DAY
#define ETHERNET_DEVICE_HPP_NEVC5DAY

#include <vanetza/net/mac_address.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <string>

class EthernetDevice
{
public:
    using protocol = boost::asio::generic::raw_protocol;

    EthernetDevice(const char* devname);
    EthernetDevice(const EthernetDevice&) = delete;
    EthernetDevice& operator=(const EthernetDevice&) = delete;
    ~EthernetDevice();

    protocol::endpoint endpoint(int family) const;
    vanetza::MacAddress address() const;
    boost::asio::ip::address_v4 ip() const;

private:
    int index() const;

    int inet_socket_;
    std::string interface_name_;
};

#endif /* ETHERNET_DEVICE_HPP_NEVC5DAY */

