cmake_minimum_required(VERSION 2.8)

find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

find_package(PROJ4 REQUIRED)
include_directories(${PROJ4_INCLUDE_DIRS})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
add_executable(sumo2nmea sumo2nmea.cc nmea.cc projector.cc)
target_link_libraries(sumo2nmea ${PROJ4_LIBRARIES})
