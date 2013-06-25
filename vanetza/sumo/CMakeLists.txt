find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

find_package(PROJ4 REQUIRED)
include_directories(${PROJ4_INCLUDE_DIRS})

vanetza_module(sumo projector.cc)
vanetza_module_dependencies(sumo ${PROJ4_LIBRARIES})

add_executable(sumo2nmea sumo2nmea.cc)
target_link_vanetza(sumo2nmea gnss sumo)
