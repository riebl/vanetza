#ifndef NETWORK_DEVICE_HPP_NEVC5DAY
#define NETWORK_DEVICE_HPP_NEVC5DAY

#include <vanetza/net/mac_address.hpp>
#include <boost/asio/generic/raw_protocol.hpp>

class NetworkDevice
{
public:
    using protocol = boost::asio::generic::raw_protocol;

    virtual protocol::endpoint endpoint(int family) const = 0;
    virtual vanetza::MacAddress address() const = 0;
};

#endif /* NETWORK_DEVICE_HPP_NEVC5DAY */
