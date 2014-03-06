include(UseGTest)
set(VANETZA_MODULE_TEST dcc)

add_gtest(ChannelLoad channel_load.cpp)
add_gtest(ChannelLoadSmoothing channel_load_smoothing.cpp)

