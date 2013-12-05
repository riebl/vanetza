include(UseGTest)

set(VANETZA_MODULE_TEST net)
add_gtest(EthernetHeader ethernet_header.cpp)
add_gtest(MacAddress mac_address.cpp)

