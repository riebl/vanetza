find_path(GeographicLib_INCLUDE_DIR NAMES GeographicLib/Config.h DOC "GeographicLib include directory")
find_library(GeographicLib_LIBRARY NAMES Geographic DOC "GeographicLib library")

if(GeographicLib_INCLUDE_DIR)
    file(STRINGS ${GeographicLib_INCLUDE_DIR}/GeographicLib/Config.h _config_version REGEX "GEOGRAPHICLIB_VERSION_STRING")
    string(REGEX MATCH "\"([0-9.]+)\"$" _match_version ${_config_version})
    set(GeographicLib_VERSION ${CMAKE_MATCH_1})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GeographicLib
    REQUIRED_VARS GeographicLib_INCLUDE_DIR GeographicLib_LIBRARY
    VERSION_VAR GeographicLib_VERSION)

if(GeographicLib_FOUND AND NOT TARGET GeographicLib::GeographicLib)
    add_library(GeographicLib::GeographicLib UNKNOWN IMPORTED GLOBAL)
    set_target_properties(GeographicLib::GeographicLib PROPERTIES
        IMPORTED_LOCATION "${GeographicLib_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${GeographicLib_INCLUDE_DIR}")
endif()

mark_as_advanced(GeographicLib_INCLUDE_DIR GeographicLib_LIBRARY)
