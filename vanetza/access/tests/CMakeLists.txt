include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES access)

add_gtest(DataRates data_rates.cpp)

