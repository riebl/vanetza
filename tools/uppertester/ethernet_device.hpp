#ifndef UPPERTESTER_ETHERNET_DEVICE_HPP
#define UPPERTESTER_ETHERNET_DEVICE_HPP

#include <vanetza/net/mac_address.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
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

private:
    int index() const;

    int local_socket_;
    std::string interface_name_;
};

#endif /* UPPERTESTER_ETHERNET_DEVICE_HPP */
