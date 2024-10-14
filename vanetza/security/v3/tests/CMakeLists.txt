include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES security)
add_gtest(Distance distance.cpp)