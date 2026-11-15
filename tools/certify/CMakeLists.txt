if(NOT TARGET Boost::program_options)
    message(STATUS "Skip build of certify because of missing Boost::program_options dependency")
    return()
endif()

if(NOT VANETZA_WITH_OPENSSL AND NOT VANETZA_WITH_CRYPTOPP AND NOT VANETZA_WITH_PSA)
    message(STATUS "Skip build of certify because no crypto provider and security module are available")
    return()
endif()

if(NOT VANETZA_WITH_PERSISTENCE)
    message(STATUS "Skip build of certify because the persistence feature is disabled")
    return()
endif()

add_executable(certify
    commands/extract-public-key.cpp
    commands/generate-aa.cpp
    commands/generate-key.cpp
    commands/generate-root.cpp
    commands/generate-ticket.cpp
    commands/migrate-key.cpp
    commands/show-certificate.cpp
    main.cpp
    options.cpp
    utils.cpp
)

target_include_directories(certify PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(certify PRIVATE cxx_std_17)
target_link_libraries(certify Boost::program_options vanetza)
