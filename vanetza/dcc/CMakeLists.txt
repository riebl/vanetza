set(CXX_SOURCES
    channel_load.cpp
)

vanetza_module(dcc ${CXX_SOURCES})

add_subdirectory(tests)

