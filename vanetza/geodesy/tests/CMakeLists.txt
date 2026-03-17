include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES geodesy)

add_gtest(Geodesy geodesy.cpp)
