#ifndef MAC_ADDRESS_HPP_FDINBLBS
#define MAC_ADDRESS_HPP_FDINBLBS

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <ostream>
#include <string>

struct sockaddr_ll;

class MacAddress
{
public:
    MacAddress();
    MacAddress(std::initializer_list<uint8_t> args);

    std::array<uint8_t, 6> octets;
};

bool parseMacAddress(const std::string&, MacAddress&);
void assignAddr(sockaddr_ll&, const MacAddress&);
std::ostream& operator<<(std::ostream& os, const MacAddress&);

#endif /* MAC_ADDRESS_HPP_FDINBLBS */
