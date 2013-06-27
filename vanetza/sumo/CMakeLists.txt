find_package(PROJ4)
if(PROJ4_FOUND)
    include_directories(${PROJ4_INCLUDE_DIRS})
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

    vanetza_module(sumo projector.cc)
    vanetza_module_dependencies(sumo ${PROJ4_LIBRARIES})

    add_executable(sumo2nmea sumo2nmea.cc)
    target_link_vanetza(sumo2nmea gnss sumo)
else()
    message(STATUS "Skip SUMO module, PROJ.4 dependency is missing")
endif(PROJ4_FOUND)
