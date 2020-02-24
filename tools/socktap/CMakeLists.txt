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

add_library(socktap-common STATIC
    application.cpp
    dcc_passthrough.cpp
    ethernet_device.cpp
    gps_position_provider.cpp
    router_context.cpp
    time_trigger.cpp
)

add_executable(socktap-hello
    hello_application.cpp
    main_hello.cpp
)

add_executable(socktap-cam
    benchmark_application.cpp
    cam_application.cpp
    main_cam.cpp
)


target_link_libraries(socktap-common PUBLIC Boost::system Boost::program_options Threads::Threads GPS::GPS vanetza)
target_link_libraries(socktap-hello socktap-common)
target_link_libraries(socktap-cam socktap-common)
install(TARGETS socktap-hello EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS socktap-cam EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

option(SOCKTAP_WITH_COHDA_LLC "Use Cohda LLC API for socktap" ${COHDA_FOUND})
if(SOCKTAP_WITH_COHDA_LLC)
    target_compile_definitions(socktap-common PUBLIC "SOCKTAP_WITH_COHDA_LLC")
    target_include_directories(socktap-common PUBLIC ${COHDA_INCLUDE_DIRS})
    target_sources(socktap-common PRIVATE cohda.cpp)
endif()
