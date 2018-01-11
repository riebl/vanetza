if(NOT TARGET Boost::system)
    message(STATUS "Skip build of uppertester because of missing Boost::system dependency")
    return()
endif()

if(NOT TARGET Boost::program_options)
    message(STATUS "Skip build of uppertester because of missing Boost::program_options dependency")
    return()
endif()

find_package(Threads REQUIRED)

add_executable(uppertester
    application.cpp
    ethernet_device.cpp
    main.cpp
    passthrough.cpp
    socket.cpp
    time_trigger.cpp
    uppertester.cpp

    trigger/btp.cpp
    trigger/btp_a.cpp
    trigger/btp_b.cpp
    trigger/common_change_position.cpp
    trigger/common_change_pseudonym.cpp
    trigger/common_ut_initialize.cpp
    trigger/common_ut_result.cpp
    trigger/trigger.cpp
)

set_target_properties(uppertester PROPERTIES INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(uppertester Boost::program_options Boost::system Threads::Threads vanetza)
