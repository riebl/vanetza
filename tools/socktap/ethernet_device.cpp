#include "ethernet_device.hpp"
#include <boost/asio/ip/address.hpp>
#include <algorithm>
#include <cstring>
#include <system_error>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>

static void initialize(ifreq& request, const char* interface_name)
{
    std::memset(&request, 0, sizeof(ifreq));
    std::strncpy(request.ifr_name, interface_name, IF_NAMESIZE);
    request.ifr_name[IF_NAMESIZE - 1] = '\0';
}

EthernetDevice::EthernetDevice(const char* devname) :
    inet_socket_(::socket(AF_INET, SOCK_DGRAM, 0)),
    interface_name_(devname)
{
    if (!inet_socket_) {
        throw std::system_error(errno, std::system_category());
    }
}

EthernetDevice::~EthernetDevice()
{
    if (inet_socket_ >= 0)
        ::close(inet_socket_);

}

EthernetDevice::protocol::endpoint EthernetDevice::endpoint(int family) const
{
    sockaddr_ll socket_address = {0};
    socket_address.sll_family = family;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = index();
    return protocol::endpoint(&socket_address, sizeof(sockaddr_ll));
}

int EthernetDevice::index() const
{
    ifreq data;
    initialize(data, interface_name_.c_str());
    ::ioctl(inet_socket_, SIOCGIFINDEX, &data);
    return data.ifr_ifindex;
}

vanetza::MacAddress EthernetDevice::address() const
{
    ifreq data;
    initialize(data, interface_name_.c_str());
    ::ioctl(inet_socket_, SIOCGIFHWADDR, &data);

    vanetza::MacAddress addr;
    std::copy_n(data.ifr_hwaddr.sa_data, addr.octets.size(), addr.octets.data());
    return addr;
}

boost::asio::ip::address_v4 EthernetDevice::ip() const
{
    ifreq data;
    initialize(data, interface_name_.c_str());
    ::ioctl(inet_socket_, SIOCGIFADDR, &data);

    char host[NI_MAXHOST] = { 0 };
    ::getnameinfo(&data.ifr_addr, sizeof(sockaddr), host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);

    return boost::asio::ip::make_address_v4(host);
}
