# FindCapnProto.cmake – thin wrapper around the upstream CapnProtoConfig.cmake
#
# The upstream CapnProtoTargets.cmake unconditionally calls add_library(... IMPORTED)
# and will therefore fail on repeated find_package() invocations in the same configure run.
# This wrapper short-circuits the second call when the targets already exist.

if(NOT TARGET CapnProto::capnp)
    # Forward to upstream CapnProtoConfig.cmake.
    # Always QUIET, find_package_handle_standard_args below controls options and output
    find_package(CapnProto CONFIG QUIET)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CapnProto CONFIG_MODE)
