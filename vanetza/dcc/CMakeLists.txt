set(CXX_SOURCES
    channel_load.cpp
    channel_load_smoothing.cpp
)

vanetza_module(dcc ${CXX_SOURCES})

add_subdirectory(tests)

