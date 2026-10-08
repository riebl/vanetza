cmake_minimum_required(VERSION 3.18)
project(VanetzaTestPackage CXX)

find_package(Vanetza REQUIRED CONFIG)

add_executable(test_package test_package.cpp)
target_link_libraries(test_package PRIVATE Vanetza::vanetza)
