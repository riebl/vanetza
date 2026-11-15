if(NOT TARGET Boost::program_options)
    message(STATUS "Skip build of benchmark because of missing Boost::program_options dependency")
    return()
endif()

if(NOT VANETZA_HAS_CRYPTO_PROVIDER OR NOT VANETZA_HAS_SECURITY_MODULE)
    message(STATUS "Skip build of benchmark because no crypto provider and security module are available")
    return()
endif()

add_executable(benchmark
    cases/security/base.cpp
    cases/security/signing.cpp
    cases/security/validation.cpp
    main.cpp
    options.cpp
)

target_include_directories(benchmark PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(benchmark Boost::program_options vanetza)
