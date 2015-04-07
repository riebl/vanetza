include(UseGTest)

set(VANETZA_MODULE_TEST btp)
add_gtest(BtpDataIndication data_indication.cpp)
add_gtest(BtpHeader header.cpp)
add_gtest(BtpPortDispatcher port_dispatcher.cpp)
