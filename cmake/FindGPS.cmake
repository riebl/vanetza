find_path(GPS_INCLUDE_DIR NAMES gps.h DOC "libgps include directory")
find_library(GPS_LIBRARY NAMES gps DOC "libgps library")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GPS
    REQUIRED_VARS GPS_INCLUDE_DIR GPS_LIBRARY)

if(GPS_FOUND AND NOT TARGET GPS::GPS)
    add_library(GPS::GPS UNKNOWN IMPORTED)
    set_target_properties(GPS::GPS PROPERTIES
        IMPORTED_LOCATION "${GPS_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${GPS_INCLUDE_DIR}")
endif()

mark_as_advanced(GPS_INCLUDE_DIR GPS_LIBRARY)
