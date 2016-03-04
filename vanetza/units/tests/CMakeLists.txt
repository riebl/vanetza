include(UseGTest)

add_gtest(Time time.cpp)
set_gtest_property(Time INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR})
