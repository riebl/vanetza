#ifndef FAKE_NETWORK_DEVICE_HPP_NEVC5DAY
#define FAKE_NETWORK_DEVICE_HPP_NEVC5DAY

#include "network_device.hpp"
#include <vanetza/net/mac_address.hpp>
#include <boost/asio/generic/raw_protocol.hpp>

class FakeNetworkDevice : public NetworkDevice
{
public:
    using protocol = boost::asio::generic::raw_protocol;

    FakeNetworkDevice(const NetworkDevice& network_device, const vanetza::MacAddress& address_override);
    FakeNetworkDevice(const FakeNetworkDevice&) = delete;
    FakeNetworkDevice& operator=(const FakeNetworkDevice&) = delete;

    protocol::endpoint endpoint(int family) const;
    vanetza::MacAddress address() const;

private:
    const NetworkDevice& network_device_;
    const vanetza::MacAddress& address_override_;
};

#endif /* FAKE_NETWORK_DEVICE_HPP_NEVC5DAY */
