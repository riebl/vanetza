#
# vanetza_optional_dependency(<package> [<version>] <option> <description>)
#
# Probe for <package> quietly, create a CMake option defaulting to whether it
# was found, and require it if the option is enabled.
#
macro(vanetza_optional_dependency package)
    if(${ARGC} EQUAL 4)
        set(_vanetza_dep_version ${ARGV1})
        set(_vanetza_dep_option ${ARGV2})
        set(_vanetza_dep_description "${ARGV3}")
    else()
        set(_vanetza_dep_version)
        set(_vanetza_dep_option ${ARGV1})
        set(_vanetza_dep_description "${ARGV2}")
    endif()
    find_package(${package} ${_vanetza_dep_version} QUIET)
    option(${_vanetza_dep_option} "${_vanetza_dep_description}" ${${package}_FOUND})
    if(${_vanetza_dep_option})
        find_package(${package} ${_vanetza_dep_version} REQUIRED)
    endif()
    unset(_vanetza_dep_version)
    unset(_vanetza_dep_option)
    unset(_vanetza_dep_description)
endmacro()

#
# add_vanetza_component(<name> <sources...>)
#
function(add_vanetza_component name)
    set(sources ${ARGN})

    add_library(${name} ${sources})
    add_library(Vanetza::${name} ALIAS ${name})
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    set_target_properties(${name} PROPERTIES
        OUTPUT_NAME vanetza_${name}
        SOVERSION ${VANETZA_SOVERSION})
    target_compile_features(${name} PUBLIC cxx_std_14)
    install(TARGETS ${name} EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_LIBDIR})
    set_property(GLOBAL APPEND PROPERTY VANETZA_COMPONENTS ${name})
endfunction()

#
# add_test_subdirectory(<directory>)
#
# Add subdirectory only when tests are enabled via BUILD_TESTS
#
function(add_test_subdirectory directory)
  if(BUILD_TESTS)
    add_subdirectory(${directory})
  endif()
endfunction(add_test_subdirectory)
