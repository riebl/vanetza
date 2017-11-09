if(NOT TARGET Boost::system)
    message(STATUS "Skip build of socktap because of missing Boost::system dependency")
    return()
endif()

if(NOT TARGET Boost::program_options)
    message(STATUS "Skip build of socktap because of missing Boost::program_options dependency")
    return()
endif()

find_package(Threads REQUIRED)
find_package(GPS REQUIRED)

add_executable(socktap
    application.cpp
    dcc_passthrough.cpp
    ethernet_device.cpp
    fake_network_device.cpp
    gps_position_provider.cpp
    hello_application.cpp
    main.cpp
    router_context.cpp
    time_trigger.cpp
)
target_link_libraries(socktap Boost::system Boost::program_options Threads::Threads GPS::GPS vanetza)
