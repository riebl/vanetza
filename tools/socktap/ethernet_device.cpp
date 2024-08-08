#include "ethernet_device.hpp"
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
    local_socket_(::socket(AF_LOCAL, SOCK_DGRAM, 0)),
    interface_name_(devname)
{
    if (!local_socket_) {
        throw std::system_error(errno, std::system_category());
    }
}

EthernetDevice::~EthernetDevice()
{
    if (local_socket_ >= 0)
        ::close(local_socket_);
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
    ::ioctl(local_socket_, SIOCGIFINDEX, &data);
    return data.ifr_ifindex;
}

vanetza::MacAddress EthernetDevice::address() const
{
    ifreq data;
    initialize(data, interface_name_.c_str());
    ::ioctl(local_socket_, SIOCGIFHWADDR, &data);

    vanetza::MacAddress addr;
    std::copy_n(data.ifr_hwaddr.sa_data, addr.octets.size(), addr.octets.data());
    return addr;
}

std::string EthernetDevice::ip() const
{
    //@todo maybe there's a better way to obtain IP from device name...
    std::string ip;
    char host[NI_MAXHOST];
    struct ifaddrs *interfaces = nullptr;
    // get all network interfaces
    if(getifaddrs(&interfaces) == 0){
        // search for local interface and copy IP
        for(struct ifaddrs *ifa = interfaces; ifa != NULL; ifa = ifa->ifa_next) {
            if(ifa->ifa_addr == NULL)
                continue;

            if(ifa->ifa_addr->sa_family == AF_INET && std::string(ifa->ifa_name) == interface_name_){
                if(getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                    ip = std::string(host);
                    break;
                }
            }
        }
        freeifaddrs(interfaces);
    }
    return ip;
}
