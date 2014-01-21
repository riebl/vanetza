set(CXX_SOURCES
    data_indication.cpp
    header.cpp
    port_dispatcher.cpp
)

vanetza_module(btp ${CXX_SOURCES})
vanetza_intermodule_dependencies(btp geonet)

add_subdirectory(tests)

