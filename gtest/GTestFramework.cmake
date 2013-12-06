set(GTest_VERSION 1.7.0)
set(GTest_ARCHIVE gtest-${GTest_VERSION}.zip)
set(GTest_ARCHIVE_SHA1 f85f6d2481e2c6c4a18539e391aa4ea8ab0394af)

set(GTest_DIR ${PROJECT_SOURCE_DIR}/gtest)
set(GTest_ARCHIVE_DIR ${GTest_DIR}/gtest-${GTest_VERSION})
set(GTest_SOURCE_DIR ${GTest_ARCHIVE_DIR}/src)
set(GTest_INCLUDE_DIR ${GTest_ARCHIVE_DIR}/include)

set(GTest_LIBRARY gtest)
set(GTest_LIBRARY_SOURCES ${GTest_SOURCE_DIR}/gtest-all.cc)
set(GTest_MAIN_LIBRARY gtest_main)
set(GTest_MAIN_LIBRARY_SOURCES ${GTest_SOURCE_DIR}/gtest_main.cc)

file(DOWNLOAD
    http://googletest.googlecode.com/files/${GTest_ARCHIVE}
    ${GTest_DIR}/${GTest_ARCHIVE}
    EXPECTED_HASH SHA1=${GTest_ARCHIVE_SHA1}
)

add_custom_command(
    OUTPUT ${GTest_LIBRARY_SOURCES} ${GTest_MAIN_LIBRARY_SOURCES}
    COMMAND ${CMAKE_COMMAND} -E tar x ${GTest_ARCHIVE}
    DEPENDS ${GTest_DIR}/${GTest_ARCHIVE}
    WORKING_DIRECTORY ${GTest_DIR}
    VERBATIM
)

add_library(${GTest_LIBRARY} ${GTest_LIBRARY_SOURCES})
add_library(${GTest_MAIN_LIBRARY} ${GTest_MAIN_LIBRARY_SOURCES})
set_target_properties(${GTest_LIBRARY} ${GTest_MAIN_LIBRARY} PROPERTIES
    INCLUDE_DIRECTORIES "${GTest_INCLUDE_DIR};${GTest_ARCHIVE_DIR}"
    INTERFACE_INCLUDE_DIRECTORIES ${GTest_INCLUDE_DIR}
)

find_library(PTHREAD_LIBRARY NAMES pthread)
if(PTHREAD_LIBRARY)
    target_link_libraries(${GTest_LIBRARY} ${PTHREAD_LIBRARY})
endif()

