find_package(Boost COMPONENTS system REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

set(CXX_SOURCES telnet_client.cc)
vanetza_module(net ${CXX_SOURCES})
vanetza_module_dependencies(net ${Boost_LIBRARIES})
