include(UseGTest)

set(VANETZA_MODULE_TEST facilities)
add_gtest(PathHistory path_history.cpp)
add_gtest(PathPoint path_point.cpp)
