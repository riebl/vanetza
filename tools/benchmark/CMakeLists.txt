if(NOT TARGET Boost::program_options)
    message(STATUS "Skip build of benchmark because of missing Boost::program_options dependency")
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
