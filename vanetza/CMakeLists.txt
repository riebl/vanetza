find_package(Boost REQUIRED)
set(VANETZA_MODULE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})

add_subdirectory(asn1)
add_subdirectory(common)
add_subdirectory(gnss)
add_subdirectory(net)

