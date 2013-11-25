include(UseGTest)

set(VANETZA_MODULE_TEST geonet)
add_gtest(Address address.cpp)
add_gtest(TrafficClass traffic_class.cpp)

