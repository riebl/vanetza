cmake_minimum_required(VERSION 2.8.12)
cmake_policy(SET CMP0022 NEW)
project(vanetza)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
include(VanetzaModule)

if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

option(ENABLE_TESTS "Build unit tests" OFF)
if(ENABLE_TESTS)
    enable_testing()
    include(gtest/GTestFramework.cmake)
endif()

add_subdirectory(vanetza)
vanetza_export_modules()

