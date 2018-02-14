if(NOT TARGET Boost::program_options)
    message(STATUS "Skip build of certify because of missing Boost::program_options dependency")
    return()
endif()

add_executable(certify
    commands/extract-public-key.cpp
    commands/generate-aa.cpp
    commands/generate-key.cpp
    commands/generate-root.cpp
    commands/generate-ticket.cpp
    commands/show-certificate.cpp
    main.cpp
    options.cpp
    utils.cpp
)

set_target_properties(certify PROPERTIES INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(certify Boost::program_options vanetza)
