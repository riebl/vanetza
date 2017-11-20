if(NOT TARGET Boost::system)
    message(STATUS "Skip build of certify because of missing Boost::system dependency")
    return()
endif()

if(NOT TARGET Boost::program_options)
    message(STATUS "Skip build of certify because of missing Boost::program_options dependency")
    return()
endif()

find_package(Threads REQUIRED)
find_package(GPS REQUIRED)

include_directories(.)

add_executable(certify
    commands/auth-ca.cpp
    commands/genkey.cpp
    commands/root-ca.cpp
    commands/sign-ticket.cpp
    keyio.cpp
    main.cpp
    options.cpp
)

target_link_libraries(certify Boost::system Boost::program_options Threads::Threads vanetza)
