#include "fake_network_device.hpp"

using boost::asio::generic::raw_protocol;

FakeNetworkDevice::FakeNetworkDevice(const NetworkDevice& network_device, const vanetza::MacAddress& address_override) :
    network_device_(network_device),
    address_override_(address_override) {}

raw_protocol::endpoint FakeNetworkDevice::endpoint(int family) const
{
    return network_device_.endpoint(family);
}

vanetza::MacAddress FakeNetworkDevice::address() const
{
    return address_override_;
}
