# Target for executing download script
add_custom_target(download_gtest
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/download_gtest.sh
    COMMENT "Fetch Goolge Testing Framework"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

set(GTest_LIBRARY_NAME gtest)
set(GTest_MAIN_LIBRARY_NAME gtest_main)

# Try to find installed GTest library and header, otherwise use sources
find_library(GTest_SYSTEM_LIBRARY ${GTest_LIBRARY_NAME})
find_library(GTest_SYSTEM_MAIN_LIBRARY ${GTest_MAIN_LIBRARY_NAME})
find_path(GTest_SYSTEM_INCLUDE_DIR gtest/gtest.h)
mark_as_advanced(GTest_SYSTEM_LIBRARY GTest_SYSTEM_MAIN_LIBRARY GTest_SYSTEM_INCLUDE_DIR)

# Force building GTest from sources
option(GTest_BUILD_FROM_SOURCES "Use GTest built from sources" ON)
mark_as_advanced(GTest_BUILD_FROM_SOURCES)

if(NOT GTest_BUILD_FROM_SOURCES
    AND GTest_SYSTEM_LIBRARY AND GTest_SYSTEM_MAIN_LIBRARY
    AND GTest_SYSTEM_INCLUDE_DIR)
    # Found GTest libraries on this system, just use them
    set(GTest_LIBRARY ${GTest_SYSTEM_LIBRARY} PARENT_SCOPE)
    set(GTest_MAIN_LIBRARY ${GTest_SYSTEM_MAIN_LIBRARY} PARENT_SCOPE)
    set(GTest_INCLUDE_DIRS ${GTest_SYSTEM_INCLUDE_DIR} PARENT_SCOPE)
    set(GTest_FOUND YES PARENT_SCOPE)
elseif(NOT WIN32)
    # Try to find GTest sources
    find_path(GTest_SOURCE_DIR src/gtest.cc PATHS gtest-src)
    mark_as_advanced(GTest_SOURCE_DIR)
    set(GTest_INCLUDE_DIRS ${GTest_SOURCE_DIR}/include)
    set(GTest_INCLUDE_DIRS ${GTest_INCLUDE_DIRS} PARENT_SCOPE)

    # Abort if GTest could not be found
    if(NOT GTest_SOURCE_DIR)
        message(STATUS "Google's testing framework NOT found")
        set(GTest_FOUND NO PARENT_SCOPE)
        return()
    endif()

    # Build GTest libraries
    include_directories(${GTest_INCLUDE_DIRS} ${GTest_SOURCE_DIR})
    add_library(${GTest_LIBRARY_NAME} ${GTest_SOURCE_DIR}/src/gtest-all.cc)
    add_library(${GTest_MAIN_LIBRARY_NAME} ${GTest_SOURCE_DIR}/src/gtest_main.cc)

    set(GTest_LIBRARY ${GTest_LIBRARY_NAME} PARENT_SCOPE)
    set(GTest_MAIN_LIBRARY ${GTest_MAIN_LIBRARY_NAME} PARENT_SCOPE)
    set(GTest_FOUND YES PARENT_SCOPE)
else()
    message(SEND_ERROR "Please set GTest variables because I can't build GTest for you.")
endif()

