# Add a test case using Google Testing Framework
## NAME name of the test case
## SRCS... variable number of source files
macro(add_gtest NAME)
  if(GTest_FOUND)
    add_executable(GTest_${NAME} ${ARGN})
    set_target_properties(GTest_${NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/tests
        INCLUDE_DIRECTORIES "${GTest_INCLUDE_DIRS};${PROJECT_SOURCE_DIR}")
    target_link_libraries(GTest_${NAME} ${GTest_MAIN_LIBRARY} ${GTest_LIBRARY})
    find_library(PTHREAD_LIBRARY NAMES pthread)
    if(PTHREAD_LIBRARY)
        target_link_libraries(GTest_${NAME} ${PTHREAD_LIBRARY})
    endif()
    if(VANETZA_MODULE_TEST)
        target_link_vanetza(GTest_${NAME} ${VANETZA_MODULE_TEST})
    endif()
    add_test(NAME ${NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND GTest_${NAME})
  endif(GTest_FOUND)
endmacro(add_gtest)

# Link libraries to a GTest
## NAME name of the test case
## LIBS... variable number of libraries
macro(link_gtest NAME)
  if(GTest_FOUND)
    target_link_libraries(GTest_${NAME} ${ARGN})
  endif(GTest_FOUND)
endmacro(link_gtest)

