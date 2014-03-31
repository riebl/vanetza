set(CXX_SOURCES
    byte_buffer_convertible.cpp
)
vanetza_module(common ${CXX_SOURCES})

add_subdirectory(tests)

