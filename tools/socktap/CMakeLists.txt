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
    #its_lci.cpp
    dcc_passthrough.cpp
    ethernet_device.cpp
    hello_application.cpp
    link_layer.cpp
    main.cpp
    #gps_position_provider.cpp
    positioning.cpp
    raw_socket_link.cpp
    router_context.cpp
    security.cpp
    tcp_link.cpp
    time_trigger.cpp
    udp_link.cpp
)

# cube evk board from nfiniity
option(SOCKTAP_WITH_CUBE_EVK "Use cube evk for socktap" OFF)
if (SOCKTAP_WITH_CUBE_EVK)
    set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
    find_package(Protobuf REQUIRED)
    protobuf_generate(TARGET socktap PROTOS nfiniity_cube_radio.proto)
    target_compile_definitions(socktap PUBLIC "SOCKTAP_WITH_CUBE_EVK")
    target_sources(socktap PRIVATE nfiniity_cube_evk_link.cpp nfiniity_cube_evk.cpp)
    target_include_directories(socktap PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(socktap PUBLIC protobuf::libprotobuf)

    if (Protobuf_VERSION VERSION_GREATER_EQUAL "22.0")
        set_property(TARGET socktap PROPERTY CXX_STANDARD 17)
    endif()
endif()

option(SOCKTAP_WITH_AUTOTALKS "Use Autotalks API for socktap" OFF) # Both Secton and Craton devices
if (SOCKTAP_WITH_AUTOTALKS)
    find_package(Autotalks MODULE REQUIRED)
    target_compile_definitions(socktap PUBLIC "SOCKTAP_WITH_AUTOTALKS")
    if(NOT AUTOTALKS_CRATON)
        target_compile_definitions(socktap PUBLIC "SECTON")
        target_link_libraries(socktap PUBLIC Boost::system Boost::program_options Threads::Threads vanetza Autotalks::AtlkRemote)
    else ()
        target_compile_definitions(socktap PUBLIC "CRATON_2")
        target_link_libraries(socktap PUBLIC Boost::system Boost::program_options Threads::Threads vanetza Autotalks::AtlkLocal)

    endif()
    target_include_directories(socktap PUBLIC ${AUTOTALKS_INCLUDE_DIRS})
    target_sources(socktap PRIVATE autotalks.cpp autotalks_link.cpp)
else()
    target_link_libraries(socktap PUBLIC Boost::system Boost::program_options Threads::Threads vanetza)
endif()

install(TARGETS socktap EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

find_file(COHDA_LLC_API_HEADER llc-api.c
    PATHS "/home/duser"
    PATH_SUFFIXES "cohda/kernel/include/linux/cohda/llc"
    CMAKE_FIND_ROOT_PATH_BOTH
    DOC "Cohda LLC API header")
mark_as_advanced(COHDA_LLC_API_HEADER)
if(COHDA_LLC_API_HEADER)
    set(COHDA_LLC_API_FOUND ON)
else()
    set(COHDA_LLC_API_FOUND OFF)
endif()

option(SOCKTAP_WITH_COHDA_LLC "Enable Cohda LLC link layer for socktap" ${COHDA_LLC_API_FOUND})
if(SOCKTAP_WITH_COHDA_LLC)
    if(NOT COHDA_LLC_API_HEADER)
        message(SEND_ERROR "Cohda LLC API header [llc-api.h] is missing")
    endif()
    get_filename_component(COHDA_LLC_INCLUDE_DIR ${COHDA_LLC_API_HEADER} DIRECTORY)
    target_compile_definitions(socktap PUBLIC "SOCKTAP_WITH_COHDA_LLC")
    target_include_directories(socktap PUBLIC ${COHDA_LLC_INCLUDE_DIR})
    target_sources(socktap PRIVATE cohda.cpp cohda_link.cpp)
endif()

find_package(GPS)
message(Found "${GPS}")
message(GPS found: "${GPS_FOUND}")
option(SOCKTAP_WITH_GPSD "Enable gpsd positioning for socktap" ${GPS_FOUND})
if(SOCKTAP_WITH_GPSD)
    message(Configuring GPS)
    find_package(GPS REQUIRED)
    target_compile_definitions(socktap PUBLIC "SOCKTAP_WITH_GPSD")
    target_link_libraries(socktap PUBLIC GPS::GPS)
    target_sources(socktap PRIVATE gps_position_provider.cpp)
endif()
