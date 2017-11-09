#ifndef ETHERNET_DEVICE_HPP_NEVC5DAY
#define ETHERNET_DEVICE_HPP_NEVC5DAY

#include "network_device.hpp"
#include <vanetza/net/mac_address.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <memory>
#include <string>

class EthernetDevice : public NetworkDevice
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

#endif /* ETHERNET_DEVICE_HPP_NEVC5DAY */
