set(CXX_SOURCES
    header.cpp
)

vanetza_module(btp ${CXX_SOURCES})
vanetza_intermodule_dependencies(btp geonet)

add_subdirectory(tests)

