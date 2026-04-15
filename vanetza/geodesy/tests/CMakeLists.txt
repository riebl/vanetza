include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES geodesy)

add_gtest(Geodesy geodesy.cpp)
add_gtest(M49Code m49_code.cpp)
add_gtest(CountryDataReader country_data_reader.cpp)
