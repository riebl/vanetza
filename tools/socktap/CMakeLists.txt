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

add_executable(socktap-hello
    application.cpp
    dcc_passthrough.cpp
    ethernet_device.cpp
    gps_position_provider.cpp
    hello_application.cpp
    main_hello.cpp
    router_context.cpp
    time_trigger.cpp
)

add_executable(socktap-cam
    application.cpp
    dcc_passthrough.cpp
    ethernet_device.cpp
    gps_position_provider.cpp
    cam_application.cpp
    main_cam.cpp
    router_context.cpp
    time_trigger.cpp
)

add_executable(socktap-bench-in
    application.cpp
    dcc_passthrough.cpp
    ethernet_device.cpp
    gps_position_provider.cpp
    bench_in_application.cpp
    cam_application.cpp
    main_bench_in.cpp
    router_context.cpp
    time_trigger.cpp
)

target_link_libraries(socktap-hello Boost::system Boost::program_options Threads::Threads GPS::GPS vanetza)
target_link_libraries(socktap-cam Boost::system Boost::program_options Threads::Threads GPS::GPS vanetza)
target_link_libraries(socktap-bench-in Boost::system Boost::program_options Threads::Threads GPS::GPS vanetza)
install(TARGETS socktap-hello EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS socktap-cam EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS socktap-bench-in EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

if(TARGET Cohda::headers)
    set_property(TARGET socktap-hello APPEND PROPERTY COMPILE_DEFINITIONS "SOCKTAP_WITH_COHDA_SDK")
    set_property(TARGET socktap-hello APPEND PROPERTY INCLUDE_DIRECTORIES "${COHDA_INCLUDE_DIRS}")
    set_property(TARGET socktap-hello APPEND PROPERTY SOURCES cohda.cpp)

    set_property(TARGET socktap-cam APPEND PROPERTY COMPILE_DEFINITIONS "SOCKTAP_WITH_COHDA_SDK")
    set_property(TARGET socktap-cam APPEND PROPERTY INCLUDE_DIRECTORIES "${COHDA_INCLUDE_DIRS}")
    set_property(TARGET socktap-cam APPEND PROPERTY SOURCES cohda.cpp)

    set_property(TARGET socktap-bench-in APPEND PROPERTY COMPILE_DEFINITIONS "SOCKTAP_WITH_COHDA_SDK")
    set_property(TARGET socktap-bench-in APPEND PROPERTY INCLUDE_DIRECTORIES "${COHDA_INCLUDE_DIRS}")
    set_property(TARGET socktap-bench-in APPEND PROPERTY SOURCES cohda.cpp)
endif()
