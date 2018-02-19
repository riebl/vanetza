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
    cam_application.cpp
    main_cam.cpp
)

add_executable(socktap-bench-in
    bench_in_application.cpp
    cam_application.cpp
    main_bench_in.cpp
)

target_link_libraries(socktap-common PUBLIC Boost::system Boost::program_options Threads::Threads GPS::GPS vanetza)
target_link_libraries(socktap-hello socktap-common)
target_link_libraries(socktap-cam socktap-common)
target_link_libraries(socktap-bench-in socktap-common)
install(TARGETS socktap-hello EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS socktap-cam EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS socktap-bench-in EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

if(TARGET Cohda::headers)
    target_compile_definitions(socktap-common PUBLIC "SOCKTAP_WITH_COHDA_SDK")
    target_include_directories(socktap-common PRIVATE "${COHDA_INCLUDE_DIRS}")
    target_sources(socktap-common PRIVATE cohda.cpp)
endif()
