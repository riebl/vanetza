#
# configure_gtest_directory(
#   [SOURCES <srcs...>]
#   [LINK_LIBRARIES <libs...>]
#   [INCLUDE_DIRECTORIES <dirs...>]
#   [COMPILE_DEFINITIONS <defs...>]
#   [COMPILE_FEATURES <features...>])
#
# Set GTest properties common for all unit test executables in current directory.
#
function(configure_gtest_directory)
  cmake_parse_arguments(args "" "" "SOURCES;LINK_LIBRARIES;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;COMPILE_FEATURES" ${ARGN})
  if(args_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR "unknown arguments given to configure_gtest_directory: ${args_UNPARSED_ARGUMENTS}")
  endif()

  set_property(DIRECTORY PROPERTY GTEST_SOURCES ${args_SOURCES})
  set_property(DIRECTORY PROPERTY GTEST_LINK_LIBRARIES ${args_LINK_LIBRARIES})
  set_property(DIRECTORY PROPERTY GTEST_INCLUDE_DIRECTORIES ${args_INCLUDE_DIRECTORIES})
  set_property(DIRECTORY PROPERTY GTEST_COMPILE_DEFINITIONS ${args_COMPILE_DEFINITIONS})
  set_property(DIRECTORY PROPERTY GTEST_COMPILE_FEATURES ${args_COMPILE_FEATURES})
endfunction()

#
# add_gtest(<name>
#   [SOURCES] <srcs...>
#   [LINK_LIBRARIES <libs...>]
#   [INCLUDE_DIRECTORIES <dirs...>]
#   [COMPILE_DEFINITIONS <defs...>]
#   [COMPILE_FEATURES <features...>])
#
# Add a CTest unit test executable using Google Test.
# The executable will be built as specified by given arguments and directory properties.
#
function(add_gtest name)
  set(target GTest_${name})
  cmake_parse_arguments(args "" "" "SOURCES;LINK_LIBRARIES;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;COMPILE_FEATURES" ${ARGN})

  get_directory_property(sources GTEST_SOURCES)
  list(APPEND sources "${args_SOURCES}" "${args_UNPARSED_ARGUMENTS}")
  get_directory_property(link_libraries GTEST_LINK_LIBRARIES)
  list(APPEND link_libraries "${args_LINK_LIBRARIES}" ${GTest_MAIN_LIBRARY})
  get_directory_property(include_directories GTEST_INCLUDE_DIRECTORIES)
  list(APPEND include_directories "${args_INCLUDE_DIRECTORIES}" ${GTest_INCLUDE_DIR})
  get_directory_property(compile_definitions GTEST_COMPILE_DEFINITIONS)
  list(APPEND compile_definitions "${args_COMPILE_DEFINITIONS}")
  get_directory_property(compile_features GTEST_COMPILE_FEATURES)
  list(APPEND compile_features "${args_COMPILE_FEATURES}")

  if(NOT sources)
    message(FATAL_ERROR "no sources given to add_gtest")
  endif()

  add_executable(${target} ${sources})
  set_target_properties(${target} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/tests
    FOLDER "GTest"
    LINK_LIBRARIES "${link_libraries}"
    INCLUDE_DIRECTORIES "${include_directories}"
    COMPILE_DEFINITIONS "${compile_definitions}"
    COMPILE_FEATURES "${compile_features}")

  # tests run in their own directories
  set(working_directory ${CMAKE_BINARY_DIR}/Testing/${name})
  file(MAKE_DIRECTORY ${working_directory})
  add_test(NAME ${name}
    WORKING_DIRECTORY ${working_directory}
    COMMAND ${target})
endfunction()
