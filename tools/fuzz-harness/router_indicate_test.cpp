#include "RouterIndicate.h"

#include <iostream>
#include <fstream>
#include <vector>


ByteBuffer readFileToByteArray(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return {};
    }

    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    ByteBuffer buffer(size);
    if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
        std::cerr << "Error reading file: " << filename << std::endl;
        return {};
    }

    return buffer;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filepath>" << std::endl;
        return 1;
    }

    const std::string filename = argv[1];
    const ByteBuffer byteArray = readFileToByteArray(filename);

    if (byteArray.empty()) {
        return 1;
    }

    RouterIndicate routerIndicate;
    routerIndicate.SetUp();

    routerIndicate.mac_address_sender = MacAddress{0xfe, 0x38, 0x4c, 0xe0, 0xb8, 0x90};
    routerIndicate.mac_address_destination = MacAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    routerIndicate.router.set_transport_handler(geonet::UpperProtocol::BTP_B, &routerIndicate.ind_ifc);
    routerIndicate.router.set_transport_handler(geonet::UpperProtocol::IPv6, nullptr);

    routerIndicate.router.indicate(routerIndicate.get_up_packet(byteArray),
                                   routerIndicate.mac_address_sender,
                                   routerIndicate.mac_address_destination);

    return 0;
}
