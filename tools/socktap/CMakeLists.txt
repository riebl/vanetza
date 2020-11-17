if(NOT TARGET Boost::system)
    message(STATUS "Skip build of socktap because of missing Boost::system dependency")
    return()
endif()

if(NOT TARGET Boost::program_options)
    message(STATUS "Skip build of socktap because of missing Boost::program_options dependency")
    return()
endif()

find_package(Threads REQUIRED)

add_executable(socktap
    application.cpp
    benchmark_application.cpp
    cam_application.cpp
    dcc_passthrough.cpp
    ethernet_device.cpp
    hello_application.cpp
    link_layer.cpp
    main.cpp
    positioning.cpp
    raw_socket_link.cpp
    router_context.cpp
    security.cpp
    time_trigger.cpp
    udp_link.cpp
)

target_link_libraries(socktap PUBLIC Boost::system Boost::program_options Threads::Threads vanetza)
install(TARGETS socktap EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

option(SOCKTAP_WITH_COHDA_LLC "Use Cohda LLC API for socktap" ${COHDA_FOUND})
if(SOCKTAP_WITH_COHDA_LLC)
    find_package(Cohda MODULE REQUIRED)
    target_compile_definitions(socktap PUBLIC "SOCKTAP_WITH_COHDA_LLC")
    target_include_directories(socktap PUBLIC ${COHDA_INCLUDE_DIRS})
    target_sources(socktap PRIVATE cohda.cpp cohda_link.cpp)
endif()

find_package(GPS QUIET)
option(SOCKTAP_WITH_GPSD "Enable gpsd positioning for socktap" ${GPS_FOUND})
if(SOCKTAP_WITH_GPSD)
    find_package(GPS REQUIRED)
    target_compile_definitions(socktap PUBLIC "SOCKTAP_WITH_GPSD")
    target_link_libraries(socktap PUBLIC GPS::GPS)
    target_sources(socktap PRIVATE gps_position_provider.cpp)
endif()
